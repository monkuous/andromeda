#pragma once

#include "fs/vfs.h"

// ctx is bdev_t *
int iso9660_create(fs_t **out, void *ctx);
