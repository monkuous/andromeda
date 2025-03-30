#pragma once

#include "fs/pgcache.h"
#include "fs/vfs.h"
#include <stdint.h>
#include <sys/types.h>

#define DRIVER_PSEUDO_FS 0
#define DRIVER_BIOSDISK 1
#define DRIVER_LOOPBACK 2

#define DEVICE_ID(driver, id) (((dev_t)(driver) << 32) | (id))

typedef struct bdev bdev_t;

typedef struct {
    int (*rvirt)(bdev_t *self, void *buffer, uint64_t block, size_t count);
    int (*rphys)(bdev_t *self, uint32_t phys, uint64_t block, size_t count);
} bdev_ops_t;

struct bdev {
    const bdev_ops_t *ops;
    uint64_t blocks;
    int block_shift;
    dev_t id;
    fs_t *fs;
};

typedef struct {
    pgcache_t base;
    bdev_t *device;
    uint64_t block;
} flat_pgcache_t;

bdev_t *resolve_bdev(dev_t device);

int open_bdev(dev_t device, file_t *file, int flags);
int open_cdev(dev_t device, file_t *file, int flags);

void init_flat_pgcache(flat_pgcache_t *cache, bdev_t *dev, uint64_t offset, uint64_t size);
