#pragma once

#include <stddef.h>

// note: these functions might allocate
int user_memcpy(void *dest, const void *src, size_t n);
int user_memset(void *dest, int value, size_t n);
