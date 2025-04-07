#include "cpu.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/usermem.h"
#include "sys/syscall.h"
#include "util/reset.h"
#include <andromeda/cpu.h>
#include <errno.h>
#include <stdint.h>

[[noreturn]] void cpu_set_registers(andromeda_cpu_regs_t *regs);

static int cpu_ioctl(file_t *, unsigned long request, void *arg) {
    switch (request) {
    case IOCTL_SET_REGISTERS: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(andromeda_cpu_regs_t));
        if (unlikely(error)) return error;

        andromeda_cpu_regs_t regs;
        error = -user_memcpy(&regs, arg, sizeof(regs));
        if (unlikely(error)) return error;

        cpu_set_registers(&regs);
    }
    case IOCTL_REBOOT: reset_system(); return 0;
    default: return -ENOTTY;
    }
}

static const file_ops_t cpu_ops = {.ioctl = cpu_ioctl};

int open_dev_cpu(file_t *file, int) {
    file->ops = &cpu_ops;
    return 0;
}
