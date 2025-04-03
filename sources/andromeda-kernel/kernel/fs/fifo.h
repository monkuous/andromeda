#pragma once

#include "fs/vfs.h"

void fifo_init(inode_t *fifo);
void fifo_no_readers(inode_t *fifo);
void fifo_no_writers(inode_t *fifo);

void fifo_open_read_cont(void *ctx);
void fifo_open_write_cont(void *ctx);
