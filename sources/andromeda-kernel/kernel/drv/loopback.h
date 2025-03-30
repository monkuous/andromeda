#pragma once

#include "drv/device.h"
#include "fs/vfs.h"
#include <sys/types.h>

int create_loopback(dev_t *out, file_t *file);
bdev_t *resolve_loopback(uint32_t minor);
