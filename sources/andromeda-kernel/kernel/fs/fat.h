#pragma once

#include "fs/vfs.h"

// ctx is bdev_t *
int fat_create(fs_t **out, void *ctx);
