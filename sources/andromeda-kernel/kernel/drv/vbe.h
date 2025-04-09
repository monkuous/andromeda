#pragma once

#include "fs/vfs.h"
#include <andromeda/video.h>
#include <stdint.h>

extern andromeda_framebuffer_t *console_fb;

void init_vbe();

int open_video(uint32_t minor, file_t *file, int flags);
