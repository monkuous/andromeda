#pragma once

#include "fs/vfs.h"
#include <stdint.h>

void init_console_early();
void init_console();
void console_set_cursor(bool cursor);

int open_console(uint32_t minor, file_t *file, int flags);

void console_write(const void *buf, size_t len);
void console_poll_events();
