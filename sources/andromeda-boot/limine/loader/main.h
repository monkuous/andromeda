#pragma once

#include "bootinfo.h"
#include <bits/ssize_t.h>
#include <stddef.h>
#include <stdint.h>

#define MIN_BASE_REV 3
#define MAX_BASE_REV 3

extern void *kernel_image;
extern size_t kernel_size;
extern uint64_t base_revision;
extern boot_info_t boot_info;
extern uint64_t boot_info_phys;

extern uint32_t kernel_cr4_value;
extern uint64_t kernel_efer_value;

extern ssize_t user_width, user_height;
extern const char *kernel_path;
extern const char *cmdline;
