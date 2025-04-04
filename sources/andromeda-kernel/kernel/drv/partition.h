#pragma once

#include "drv/device.h"
#include <stdint.h>

typedef void (*part_cb_t)(uint64_t lba, uint64_t size, const void *id, size_t id_len, void *ctx);

int discover_partitions(bdev_t *bdev, const void *name, size_t length, part_cb_t cb, void *ctx);
