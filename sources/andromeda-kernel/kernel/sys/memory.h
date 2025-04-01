#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int64_t sys_MMAP(uintptr_t hint, size_t len, int fprot, int fd, off_t idx);
int sys_MUNMAP(uintptr_t addr, size_t size);
