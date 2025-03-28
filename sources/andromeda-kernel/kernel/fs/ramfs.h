#pragma once

#include "fs/vfs.h"

struct ramfs_create_ctx {
    mode_t mode;
};

fs_t *ramfs_create(void *ctx);
