#include "memory.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/pmem.h"
#include "mem/vmm.h"
#include "proc/exec.h"
#include "proc/process.h"
#include "sys/syscall.h"
#include <andromeda/string.h>
#include <stdint.h>
#include <sys/mman.h>

int64_t sys_MMAP(uintptr_t hint, size_t len, int fprot, int fd, off_t idx) {
    int flags = fprot & 0xfffffff;
    int prot = fprot >> 28;
    int error;
    file_t *file = nullptr;

    if (!(flags & MAP_ANON)) {
        error = -fd_lookup(&file, fd);
        if (unlikely(error)) return error;
    }

    error = -vm_map(&hint, len, flags, prot, file, (uint64_t)idx << PAGE_SHIFT);
    if (file) file_deref(file);
    if (unlikely(error)) return error;

    return hint;
}

int sys_MUNMAP(uintptr_t addr, size_t size) {
    return -vm_unmap(addr, size);
}

int sys_EXEC(int fd, uintptr_t argv, size_t narg, uintptr_t envp, size_t nenv) {
    int error = -verify_pointer(argv, narg * sizeof(andromeda_tagged_string_t));
    if (unlikely(error)) return error;

    error = -verify_pointer(envp, nenv * sizeof(andromeda_tagged_string_t));
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -execute(file, (const void *)argv, narg, (const void *)envp, nenv, true);
    file_deref(file);
    return error;
}
