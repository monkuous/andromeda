#pragma once

#include "bootinfo.h"

extern boot_info_t *boot_info;

[[noreturn]] void die();
