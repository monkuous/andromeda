#pragma once

#include "fs/vfs.h"
#include <stdint.h>

void init_console_early();
void init_console();

int open_console(uint32_t minor, file_t *file, int flags);

void console_write(const void *buf, size_t len);
void console_poll_events();

void console_disconnect_from_session(bool on_exit);
void console_disconnect_from_group();
