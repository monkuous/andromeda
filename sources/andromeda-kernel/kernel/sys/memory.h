#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int64_t sys_MMAP(uintptr_t hint, size_t len, int fprot, int fd, uint32_t off_low, uint32_t off_high);
int sys_MUNMAP(uintptr_t addr, size_t size);
int sys_EXEC(int fd, uintptr_t argv, size_t narg, uintptr_t envp, size_t nenv);
