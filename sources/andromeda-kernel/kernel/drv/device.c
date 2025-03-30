#include "device.h"
#include "compiler.h"
#include "drv/biosdisk.h"
#include "fs/vfs.h"
#include "string.h"
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
