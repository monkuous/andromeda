#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

extern void *hostname;
extern size_t hostname_len;

ssize_t sys_GETHOSTNAME(uintptr_t buffer, size_t size);
int sys_SETHOSTNAME(uintptr_t buffer, size_t size);
int sys_UNAME(uintptr_t buffer);
