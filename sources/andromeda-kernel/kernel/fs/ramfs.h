#pragma once

#include "fs/vfs.h"

struct ramfs_create_ctx {
    mode_t mode;
};

int ramfs_create(fs_t **out, void *ctx);
