#include "loopback.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "string.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_READ 0x7fff0000
#define BUF_SIZE PAGE_SIZE

typedef struct {
    bdev_t base;
    file_t *file;
    unsigned char *buffer;
} loopback_bdev_t;

static int loopback_read(bdev_t *ptr, uint32_t phys, uint64_t block, size_t count) {
    loopback_bdev_t *self = (loopback_bdev_t *)ptr;

    uint64_t off = block << ptr->block_shift;
    uint64_t rem = (uint64_t)count << ptr->block_shift;

    uint32_t pgoff = phys & PAGE_MASK;
    ssize_t pgrem = PAGE_SIZE - pgoff;

    while (rem > 0) {
        ssize_t cur = rem < BUF_SIZE ? rem : BUF_SIZE;
        if (cur > pgrem) cur = pgrem;

        ssize_t done = vfs_pread(self->file, self->buffer, cur, off);
        if (unlikely(done < 0)) return -done;

        void *ptr = pmap_tmpmap(phys & ~PAGE_MASK) + pgoff;
        memcpy(ptr, self->buffer, done);

        if (done != cur) {
            memset(ptr + done, 0, cur - done);
            break;
        }

        phys += cur;
        off += cur;
        rem -= cur;
        pgoff = 0;
        pgrem = PAGE_SIZE;
    }

    return 0;
}

static const bdev_ops_t loopback_ops = {
        .read = loopback_read,
};

static loopback_bdev_t **loopbacks;
static size_t num_loopbacks;

static size_t expand_loopbacks() {
    size_t old_size = num_loopbacks * sizeof(*loopbacks);
    size_t new_size = old_size + sizeof(*loopbacks);
    loopback_bdev_t **new_list = vmalloc(new_size);
    memcpy(new_list, loopbacks, old_size);
    vmfree(loopbacks, old_size);
    loopbacks = new_list;
    return num_loopbacks++;
}

int create_loopback(dev_t *out, file_t *file, size_t block_size) {
    if (block_size & (block_size - 1)) return EINVAL;

    int error = access_file(file, R_OK);
    if (unlikely(error)) return error;

    struct stat stat;
    error = vfs_fstat(file, &stat);
    if (unlikely(error)) return EINVAL;
    if (unlikely(!S_ISREG(stat.st_mode))) return EINVAL;
    if (unlikely(stat.st_blksize & (stat.st_blksize - 1))) return EINVAL;

    size_t minor = expand_loopbacks();
    dev_t id = DEVICE_ID(DRIVER_LOOPBACK, minor);

    loopback_bdev_t *device = loopbacks[id] = vmalloc(sizeof(*device));
    memset(device, 0, sizeof(*device));
    device->base.ops = &loopback_ops;
    device->base.block_shift = __builtin_ctz(block_size);
    device->base.blocks = (stat.st_size + (block_size - 1)) >> device->base.block_shift;
    device->base.id = id;
    device->file = file;
    device->buffer = vmalloc(BUF_SIZE);
    file_ref(file);
    init_bdev_pgcache(&device->base);

    *out = id;
    return 0;
}

bdev_t *resolve_loopback(uint32_t minor) {
    if (minor >= num_loopbacks) return nullptr;
    return &loopbacks[minor]->base;
}
