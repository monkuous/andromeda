#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int64_t sys_MMAP(uintptr_t hint, size_t len, int fprot, int fd, off_t idx);
int sys_MUNMAP(uintptr_t addr, size_t size);
int sys_EXEC(int fd, uintptr_t argv, size_t narg, uintptr_t envp, size_t nenv);
