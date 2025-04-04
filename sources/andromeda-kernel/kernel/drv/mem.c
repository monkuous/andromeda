#include "mem.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "sys/syscall.h"
#include <andromeda/memory.h>
#include <errno.h>
#include <sys/mman.h>
#include <unistd.h>

static int dev_mem_seek(file_t *self, uint64_t *offset, int whence) {
    switch (whence) {
    case SEEK_SET: return 0;
    case SEEK_CUR: *offset += self->position; return 0;
    default: return EINVAL;
    }
}

static int dev_mem_op(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos, bool write) {
    uint32_t available;
    if (offset < UINT32_MAX) available = UINT32_MAX - offset + 1;
    else available = 0;

    size_t remaining = *size;
    if (remaining > available) remaining = available;
    size_t total = remaining;

    while (remaining) {
        size_t pgoff = offset & PAGE_MASK;
        size_t pgrem = PAGE_SIZE - pgoff;
        size_t cur = pgrem < remaining ? pgrem : remaining;

        int error;

        if (write) error = user_memcpy(pmap_tmpmap(offset - pgoff) + pgoff, buffer, cur);
        else error = user_memcpy(buffer, pmap_tmpmap(offset - pgoff) + pgoff, cur);

        if (unlikely(error)) return error;

        buffer += cur;
        offset += cur;
        remaining -= cur;
    }

    if (update_pos) self->position = offset;
    *size = total;
    return 0;
}

static int dev_mem_read(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    return dev_mem_op(self, buffer, size, offset, update_pos, false);
}

static int dev_mem_write(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    return dev_mem_op(self, buffer, size, offset, update_pos, true);
}

static void dev_mem_mmap(file_t *, uintptr_t head, uintptr_t tail, uint64_t offset, int, int prot) {
    if (offset > UINT32_MAX) return;

    uint32_t avail = UINT32_MAX - offset;
    uint32_t req = tail - head + 1;
    if (req > avail) req = avail;

    pmap_map(head, offset, req, prot & PROT_WRITE ? PMAP_WRITABLE : 0);
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

static const file_ops_t pmalloc_file_ops = {.free = pmalloc_file_free};

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

        inode_t *inode = create_anonymous_inode(S_IFCHR, DEVICE_ID(DRIVER_RESERVED, 0));
        file_t *file;
        error = -open_inode(&file, nullptr, inode, O_PATH);
        if (unlikely(error)) {
            fd_free(fd);
            pmem_free_multiple(page, data.pages);
            return error;
        }

        pmalloc_data_t *fdat = vmalloc(sizeof(*fdat));
        fdat->page = page;
        fdat->count = data.pages;
        file->ops = &pmalloc_file_ops;
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
