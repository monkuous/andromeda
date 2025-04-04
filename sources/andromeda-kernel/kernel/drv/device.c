#include "device.h"
#include "compiler.h"
#include "drv/biosdisk.h"
#include "drv/console.h"
#include "drv/loopback.h"
#include "fs/pgcache.h"
#include "fs/vfs.h"
#include "mem/pmem.h"
#include "string.h"
#include "util/panic.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <unistd.h>

bdev_t *resolve_bdev(dev_t device) {
    switch (device >> 32) {
    case DRIVER_BIOSDISK: return resolve_biosdisk(device);
    case DRIVER_LOOPBACK: return resolve_loopback(device);
    default: return nullptr;
    }
}

static int bdev_file_seek(file_t *self, uint64_t *offset, int whence) {
    bdev_t *bdev = self->priv;

    switch (whence) {
    case SEEK_SET: break;
    case SEEK_CUR: *offset += self->position; break;
    case SEEK_END: *offset += bdev->blocks << bdev->block_shift; break;
    default: return EINVAL;
    }

    return 0;
}

static int bdev_file_read(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    bdev_t *bdev = self->priv;

    size_t remaining = *size;
    uint64_t available = bdev->blocks << bdev->block_shift;
    if (available > offset) available -= offset;
    else available = 0;
    if (remaining > available) remaining = available;

    if (remaining) {
        int error = pgcache_read(&bdev->data, buffer, remaining, offset);
        if (unlikely(error)) return error;
    }

    if (update_pos) self->position = offset + remaining;
    *size = remaining;
    return 0;
}

static const file_ops_t bdev_file_ops = {
        .seek = bdev_file_seek,
        .read = bdev_file_read,
};

int open_bdev(dev_t device, file_t *file, int flags) {
    if ((flags & O_ACCMODE) != O_RDONLY) return ENXIO;

    bdev_t *dev = resolve_bdev(device);
    if (unlikely(!dev)) return ENXIO;

    file->ops = &bdev_file_ops;
    file->priv = dev;

    return 0;
}

int open_cdev(dev_t device, file_t *file, int flags) {
    switch (device >> 32) {
    case DRIVER_CONSOLE: return open_console(device, file, flags);
    default: return ENXIO;
    }
}

static int bdev_pgcache_read_page(pgcache_t *ptr, page_t *page, uint64_t idx) {
    bdev_t *device = container(bdev_t, data, ptr);

    uint64_t block = idx << (PAGE_SHIFT - device->block_shift);
    uint64_t count = device->blocks - block;
    size_t rqcount = PAGE_SIZE >> device->block_shift;
    if (rqcount > count) rqcount = count;

    return device->ops->read(device, page_to_phys(page), block, rqcount);
}

static const pgcache_ops_t bdev_pgcache_ops = {
    .read_page = bdev_pgcache_read_page,
};

void init_bdev_pgcache(bdev_t *dev) {
    ASSERT(dev->block_shift <= PAGE_SHIFT);
    dev->data.ops = &bdev_pgcache_ops;
    pgcache_resize(&dev->data, dev->blocks << dev->block_shift);
}
