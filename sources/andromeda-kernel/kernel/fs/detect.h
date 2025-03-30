#pragma once

#include "fs/vfs.h"

// ctx is bdev_t *
int fsdetect(fs_t **out, void *ctx);
