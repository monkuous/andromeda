#include "syscall.h"
#include "compiler.h"
#include "mem/layout.h"
#include "sys/fs.h"     /* IWYU pragma: keep */
#include "sys/memory.h" /* IWYU pragma: keep */
#include "sys/misc.h"   /* IWYU pragma: keep */
#include "sys/thread.h" /* IWYU pragma: keep */
#include <andromeda/syscall.h>
#include <errno.h>
#include <stdint.h>

#define LOG_SYSCALLS_NONE 0
#define LOG_SYSCALLS_ERROR 1
#define LOG_SYSCALLS_ALL 2

#define LOG_SYSCALLS LOG_SYSCALLS_NONE

#if LOG_SYSCALLS
#include "util/print.h"

static void log_syscall_start(const char *name, int count, va_list args) {
    printk("syscall: %s(", name);

    while (count) {
        printk("0x%x", va_arg(args, unsigned long));
        if (--count) printk(", ");
    }

    printk(") ");
}

static void log_syscall_ret(int64_t value) {
    if (likely(value >= 0)) {
        printk("-> 0x%X\n", value);
    } else {
        printk("-> %d\n", (int)value);
    }
}

static void log_pre_syscall([[maybe_unused]] const char *name, [[maybe_unused]] int count, ...) {
#if LOG_SYSCALLS > LOG_SYSCALLS_ERROR
    va_list args;
    va_start(args, count);
    log_syscall_start(name, count, args);
    va_end(args);
#endif
}

static int64_t log_post_syscall(int64_t value, [[maybe_unused]] const char *name, [[maybe_unused]] int count, ...) {
#if LOG_SYSCALLS <= LOG_SYSCALLS_ERROR
    if (likely(value >= 0)) return value;

    va_list args;
    va_start(args, count);
    log_syscall_start(name, count, args);
    va_end(args);
#endif

    log_syscall_ret((int)value);
    return value;
}

#define SYSWRAP(name, n, x, ...)                                                                                       \
    ({                                                                                                                 \
        log_pre_syscall(#name, n, __VA_ARGS__);                                                                        \
        log_post_syscall(x(__VA_ARGS__), #name, n, __VA_ARGS__);                                                       \
    })
#else
#define SYSWRAP(name, n, x, ...) (x(__VA_ARGS__))
#endif

void handle_syscall(idt_frame_t *frame) {
#define SYSHANDLER0(name) SYSWRAP(name, 0, sys_##name)
#define SYSHANDLER1(name) SYSWRAP(name, 1, sys_##name, frame->ebx)
#define SYSHANDLER2(name) SYSWRAP(name, 2, sys_##name, frame->ebx, frame->ecx)
#define SYSHANDLER3(name) SYSWRAP(name, 3, sys_##name, frame->ebx, frame->ecx, frame->edx)
#define SYSHANDLER4(name) SYSWRAP(name, 4, sys_##name, frame->ebx, frame->ecx, frame->edx, frame->esi)
#define SYSHANDLER5(name) SYSWRAP(name, 5, sys_##name, frame->ebx, frame->ecx, frame->edx, frame->esi, frame->edi)

    switch (frame->eax) {
#define SYSHANDLER32(name, num)                                                                                        \
    case SYS_##name: frame->eax = SYSHANDLER##num(name); break;
#define SYSHANDLER64(name, num)                                                                                        \
    case SYS_##name: {                                                                                                 \
        int64_t ret = SYSHANDLER##num(name);                                                                           \
        frame->eax = ret >> 32;                                                                                        \
        frame->edx = ret;                                                                                              \
        break;                                                                                                         \
    }
        SYSHANDLER32(KLOG, 2)
        SYSHANDLER64(MMAP, 5)
        SYSHANDLER32(MUNMAP, 2)
        SYSHANDLER32(SET_TCB, 1)
        SYSHANDLER32(OPEN, 5)
        SYSHANDLER64(SEEK, 3)
        SYSHANDLER32(READ, 3)
        SYSHANDLER32(CLOSE, 1)
        SYSHANDLER32(EXIT, 1)
        SYSHANDLER32(WRITE, 3)
        SYSHANDLER32(IOCTL, 3)
        SYSHANDLER32(FCNTL, 3)
        SYSHANDLER32(DUP, 2)
        SYSHANDLER32(DUP2, 3)
    default:
#if LOG_SYSCALLS
        printk("syscall: unknown syscall %u\n", frame->eax);
#endif
        frame->eax = -ENOSYS;
        break;
#undef SYSHANDLER32
#undef SYSHANDLER64
    }
#undef SYSHANDLER0
#undef SYSHANDLER1
#undef SYSHANDLER2
#undef SYSHANDLER3
#undef SYSHANDLER4
#undef SYSHANDLER5
}

int verify_pointer(uintptr_t ptr, size_t size) {
    uintptr_t end = ptr + size;
    if (unlikely(end < ptr)) return EFAULT;
    if (unlikely(end > KERN_VIRT_BASE)) return EFAULT;
    return 0;
}
