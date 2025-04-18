#include "mem.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "mem/bootmem.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "sys/syscall.h"
#include <andromeda/memory.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <unistd.h>

static int dev_mem_seek(file_t *self, uint64_t *offset, int whence) {
    switch (whence) {
    case SEEK_SET: return 0;
    case SEEK_CUR: *offset += self->position; return 0;
    default: return EINVAL;
    }
}

static int do_dev_mem_op(
        file_t *self,
        void *buffer,
        size_t *size,
        uint64_t offset,
        bool update_pos,
        bool write,
        uint64_t base,
        uint64_t max
) {
    max = (max - 1) + base;

    uint64_t available;
    if (offset < max) available = max - offset + 1;
    else available = 0;

    size_t remaining = *size;
    if (remaining > available) remaining = available;
    size_t total = remaining;

    while (remaining) {
        size_t pgoff = offset & PAGE_MASK;
        size_t pgrem = PAGE_SIZE - pgoff;
        size_t cur = pgrem < remaining ? pgrem : remaining;

        int error;

        void *physptr = pmap_tmpmap(offset - pgoff + base) + pgoff;

        if (write) error = user_memcpy(physptr, buffer, cur);
        else error = user_memcpy(buffer, physptr, cur);

        if (unlikely(error)) return error;

        buffer += cur;
        offset += cur;
        remaining -= cur;
    }

    if (update_pos) self->position = offset;
    *size = total;
    return 0;
}

struct dmop_ctx {
    file_t *file;
    void *buffer;
    uint64_t pbase;
    uint64_t last_end;
    bool update_pos;
    bool write;
    int error;
};

static bool dmop_cb(uint64_t head, uint64_t tail, void *ptr) {
    struct dmop_ctx *ctx = ptr;

    if (head != ctx->last_end) {
        ctx->error = user_memset(ctx->buffer + (ctx->last_end - ctx->pbase), 0, head - ctx->last_end);
        if (unlikely(ctx->error)) return false;
    }

    uint64_t requested = (tail - head) + 1;
    size_t size = requested < 0xffffffff ? requested : 0xffffffff;
    ctx->error = do_dev_mem_op(
            ctx->file,
            ctx->buffer + (head - ctx->pbase),
            &size,
            head,
            ctx->update_pos,
            ctx->write,
            0,
            UINT32_MAX
    );
    if (unlikely(ctx->error)) return false;
    if (size) ctx->last_end = head + size;

    return size == requested;
}

static int dev_mem_op(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos, bool write) {
    struct dmop_ctx ctx = {self, buffer, offset, offset, update_pos, write, 0};
    bootmem_iter_nonusable(offset, offset + (*size - 1), dmop_cb, &ctx);
    if (unlikely(ctx.error)) return ctx.error;

    size_t total = ctx.last_end - offset;
    *size = total;
    return 0;
}

static int dev_mem_read(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    return dev_mem_op(self, buffer, size, offset, update_pos, false);
}

static int dev_mem_write(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    return dev_mem_op(self, buffer, size, offset, update_pos, true);
}

struct dev_mem_mmap_ctx {
    uintptr_t vhead;
    uint64_t phead;
    uint32_t flags;
};

static bool dev_mem_mmap_cb(uint64_t head, uint64_t tail, void *ptr) {
    if (head > UINT32_MAX) return false;

    uint32_t avail = UINT32_MAX - head;
    uint32_t req = tail - head;
    uint32_t cur = req < avail ? req : avail;

    struct dev_mem_mmap_ctx *ctx = ptr;
    pmap_map(ctx->vhead + (head - ctx->phead), head, cur + 1, ctx->flags);

    return cur == req;
}

static void dev_mem_mmap(file_t *, uintptr_t head, uintptr_t tail, uint64_t offset, int, int prot) {
    struct dev_mem_mmap_ctx ctx = {
            .vhead = head,
            .phead = offset,
            .flags = prot & PROT_WRITE ? PMAP_WRITABLE : 0,
    };
    bootmem_iter_nonusable(ctx.phead, (tail - head) + offset, dev_mem_mmap_cb, &ctx);
}

typedef struct {
    page_t *page;
    size_t count;
} pmalloc_data_t;

static void pmalloc_file_free(file_t *ptr) {
    pmalloc_data_t *data = ptr->priv;
    pmem_free_multiple(data->page, data->count);
    vmfree(data, sizeof(*data));
}

static int pmalloc_file_seek(file_t *self, uint64_t *offset, int whence) {
    switch (whence) {
    case SEEK_SET: return 0;
    case SEEK_CUR: *offset += self->position; return 0;
    default: return EINVAL;
    }
}

static int pmalloc_file_read(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    pmalloc_data_t *data = self->priv;
    return do_dev_mem_op(
            self,
            buffer,
            size,
            offset,
            update_pos,
            false,
            page_to_phys(data->page),
            (uint64_t)data->count << PAGE_SHIFT
    );
}

static int pmalloc_file_write(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    pmalloc_data_t *data = self->priv;
    return do_dev_mem_op(
            self,
            buffer,
            size,
            offset,
            update_pos,
            true,
            page_to_phys(data->page),
            (uint64_t)data->count << PAGE_SHIFT
    );
}

static void pmalloc_file_mmap(file_t *self, uintptr_t head, uintptr_t tail, uint64_t offset, int, int prot) {
    pmalloc_data_t *data = self->priv;
    uint32_t max = (data->count << PAGE_SHIFT) - 1;
    if (offset > max) return;

    uint32_t avail = max - offset;
    uint32_t req = tail - head;
    if (req > avail) req = avail;

    pmap_map(head, page_to_phys(data->page) + offset, req + 1, prot & PROT_WRITE ? PMAP_WRITABLE : 0);
}

static const file_ops_t pmalloc_file_ops = {
        .free = pmalloc_file_free,
        .seek = pmalloc_file_seek,
        .read = pmalloc_file_read,
        .write = pmalloc_file_write,
        .mmap = pmalloc_file_mmap,
};

static int dev_mem_ioctl(file_t *, unsigned long request, void *arg) {
    switch (request) {
    case IOCTL_PMALLOC: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(andromeda_pmalloc_t));
        if (unlikely(error)) return error;

        andromeda_pmalloc_t data;
        error = -user_memcpy(&data, arg, sizeof(data));
        if (unlikely(error)) return error;

        if (data.flags & ~(O_CLOEXEC)) return -EINVAL;

        page_t *page;
        error = -pmem_alloc_slow(&page, data.pages, data.align, data.addr < UINT32_MAX ? data.addr : UINT32_MAX);
        if (unlikely(error)) return error;
        data.addr = page_to_phys(page);

        int fd = fd_alloc();
        if (unlikely(fd < 0)) {
            pmem_free_multiple(page, data.pages);
            return fd;
        }

        inode_t *inode = create_anonymous_inode(S_IFCHR, DEVICE_ID(DRIVER_RESERVED, next_reserved_minor()));
        file_t *file;
        error = -open_inode(&file, nullptr, inode, O_RDWR, &pmalloc_file_ops);
        if (unlikely(error)) {
            fd_free(fd);
            pmem_free_multiple(page, data.pages);
            return error;
        }

        pmalloc_data_t *fdat = vmalloc(sizeof(*fdat));
        fdat->page = page;
        fdat->count = data.pages;
        file->priv = fdat;

        error = -user_memcpy(arg, &data, sizeof(data));
        if (unlikely(error)) {
            file_deref(file);
            fd_free(fd);
            pmem_free_multiple(page, data.pages);
            return error;
        }

        fd_assoc(fd, file, data.flags & O_CLOEXEC ? FD_CLOEXEC : 0);
        file_deref(file);
        return fd;
    }
    default: return -ENOTTY;
    }
}

static const file_ops_t dev_mem_ops = {
        .seek = dev_mem_seek,
        .read = dev_mem_read,
        .write = dev_mem_write,
        .mmap = dev_mem_mmap,
        .ioctl = dev_mem_ioctl,
};

int open_dev_mem(file_t *file, int) {
    file->ops = &dev_mem_ops;
    return 0;
}
