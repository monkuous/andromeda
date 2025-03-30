#include "device.h"
#include "compiler.h"
#include "drv/biosdisk.h"
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

    int bshift = bdev->block_shift;
    size_t block_size = 1ul << bshift;
    size_t block_mask = block_size - 1;

    if (offset & block_mask) return ENXIO;

    size_t remaining = *size;
    uint64_t available = bdev->blocks << bshift;
    if (available > offset) available -= offset;
    else available = 0;
    if (remaining > available) remaining = available;

    if ((offset | remaining) & block_mask) return ENXIO;

    int error = bdev->ops->rvirt(bdev, buffer, offset >> bshift, remaining >> bshift);
    if (unlikely(error)) return error;

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

int open_cdev(dev_t, file_t *, int) {
    return ENXIO;
}

static int flat_pgcache_read_page(pgcache_t *ptr, page_t *page, uint64_t idx) {
    flat_pgcache_t *self = (flat_pgcache_t *)ptr;
    uint64_t block = self->block + (idx << (PAGE_SHIFT - self->device->block_shift));
    size_t count = PAGE_SIZE >> self->device->block_shift;

    return self->device->ops->rphys(self->device, page_to_phys(page), block, count);
}

static const pgcache_ops_t flat_pgcache_ops = {
    .read_page = flat_pgcache_read_page,
};

void init_flat_pgcache(flat_pgcache_t *cache, bdev_t *dev, uint64_t offset, uint64_t size) {
    ASSERT(size);
    ASSERT(!(offset & ((1ul << dev->block_shift) - 1)));
    ASSERT(((offset + (size - 1)) >> dev->block_shift) < dev->blocks);
    ASSERT(dev->block_shift <= PAGE_SHIFT);

    cache->base.ops = &flat_pgcache_ops;
    cache->device = dev;
    cache->block = offset >> dev->block_shift;

    pgcache_resize(&cache->base, size);
}
