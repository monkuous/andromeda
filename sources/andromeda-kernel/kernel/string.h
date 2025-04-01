#pragma once

#include <stddef.h>

#define memcmp __builtin_memcmp
#define memcpy __builtin_memcpy
#define memmove __builtin_memmove
#define memset __builtin_memset

size_t strnlen(const char *s, size_t maxlen);
