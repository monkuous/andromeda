#pragma once

#include "fs/vfs.h"
#include <sys/types.h>

#define DRIVER_PSEUDO_FS 0

#define DEVICE_ID(driver, id) (((dev_t)(driver) << 32) | (id))

int open_bdev(dev_t device, file_t *file, int flags);
int open_cdev(dev_t device, file_t *file, int flags);
