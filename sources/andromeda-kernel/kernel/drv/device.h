#pragma once

#include "fs/pgcache.h"
#include "fs/vfs.h"
#include <stdint.h>
#include <sys/types.h>

#define DRIVER_PSEUDO_FS 0
#define DRIVER_BIOSDISK 1
#define DRIVER_LOOPBACK 2
#define DRIVER_CONSOLE 3

#define DEVICE_ID(driver, id) (((dev_t)(driver) << 32) | (id))

typedef struct bdev bdev_t;

typedef struct {
    int (*read)(bdev_t *self, uint32_t phys, uint64_t block, size_t count);
} bdev_ops_t;

struct bdev {
    const bdev_ops_t *ops;
    pgcache_t data;
    uint64_t blocks;
    int block_shift;
    dev_t id;
    fs_t *fs;
};

bdev_t *resolve_bdev(dev_t device);

int open_bdev(dev_t device, file_t *file, int flags);
int open_cdev(dev_t device, file_t *file, int flags);

void init_bdev_pgcache(bdev_t *dev);
