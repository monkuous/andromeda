#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int64_t sys_MMAP(uintptr_t hint, size_t len, int fprot, int fd, uint32_t off_low, uint32_t off_high);
int sys_MUNMAP(uintptr_t addr, size_t size);
int sys_FUTEX_WAKE(uintptr_t addr);
int sys_FUTEX_WAIT(uintptr_t addr, int expected, uint32_t tm_sec_low, uint32_t tm_sec_high, int32_t tm_nsec);
int sys_EXEC(int fd, uintptr_t argv, size_t narg, uintptr_t envp, size_t nenv);
int sys_MPROTECT(uintptr_t addr, size_t size, int prot);
