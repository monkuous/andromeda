#include "syscall.h"
#include "compiler.h"
#include "mem/layout.h"
#include "proc/sched.h"
#include "sys/fs.h"      /* IWYU pragma: keep */
#include "sys/memory.h"  /* IWYU pragma: keep */
#include "sys/misc.h"    /* IWYU pragma: keep */
#include "sys/process.h" /* IWYU pragma: keep*/
#include "sys/sched.h"   /* IWYU pragma: keep */
#include "sys/system.h"  /* IWYU pragma: keep */
#include "sys/thread.h"  /* IWYU pragma: keep */
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
        log_pre_syscall(#name, n, ##__VA_ARGS__);                                                                      \
        log_post_syscall(x(__VA_ARGS__), #name, n, ##__VA_ARGS__);                                                     \
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
#define SYSHANDLER6(name)                                                                                              \
    SYSWRAP(name, 6, sys_##name, frame->ebx, frame->ecx, frame->edx, frame->esi, frame->edi, frame->ebp)

    switch (frame->eax) {
#define SYSHANDLER32(name, num)                                                                                        \
    case SYS_##name: {                                                                                                 \
        int ret = SYSHANDLER##num(name);                                                                               \
        if (frame->vector == 0x20) frame->eax = ret;                                                                   \
        break;                                                                                                         \
    }
#define SYSHANDLER64(name, num)                                                                                        \
    case SYS_##name: {                                                                                                 \
        int64_t ret = SYSHANDLER##num(name);                                                                           \
        if (frame->vector == 0x20) {                                                                                   \
            if (unlikely(ret < 0)) {                                                                                   \
                frame->eax = ret;                                                                                      \
            } else {                                                                                                   \
                frame->eax = ret >> 32;                                                                                \
                frame->edx = ret;                                                                                      \
            }                                                                                                          \
        }                                                                                                              \
        break;                                                                                                         \
    }
        SYSHANDLER32(KLOG, 2)
        SYSHANDLER64(MMAP, 6)
        SYSHANDLER32(MUNMAP, 2)
        SYSHANDLER32(SET_TCB, 1)
        SYSHANDLER32(FUTEX_WAKE, 1)
        SYSHANDLER32(FUTEX_WAIT, 5)
        SYSHANDLER32(OPEN, 5)
        SYSHANDLER64(SEEK, 4)
        SYSHANDLER32(READ, 3)
        SYSHANDLER32(CLOSE, 1)
        SYSHANDLER32(EXIT, 1)
        SYSHANDLER32(WRITE, 3)
        SYSHANDLER32(IOCTL, 3)
        SYSHANDLER32(FCNTL, 3)
        SYSHANDLER32(DUP, 2)
        SYSHANDLER32(DUP2, 3)
        SYSHANDLER32(GETUID, 0)
        SYSHANDLER32(GETGID, 0)
        SYSHANDLER32(GETEUID, 0)
        SYSHANDLER32(GETEGID, 0)
        SYSHANDLER32(GETPID, 0)
        SYSHANDLER32(GETPPID, 0)
        SYSHANDLER32(GETPGID, 1)
        SYSHANDLER32(STAT, 5)
        SYSHANDLER32(FSTAT, 2)
        SYSHANDLER32(PSELECT, 6)
        SYSHANDLER32(SIGPROCMASK, 3)
        SYSHANDLER32(SIGACTION, 3)
        SYSHANDLER32(SIGRETURN, 0)
        SYSHANDLER32(ACCESS, 5)
        SYSHANDLER32(FORK, 0)
        SYSHANDLER32(EXEC, 5)
        SYSHANDLER32(PWAIT, 3)
        SYSHANDLER32(KILL, 2)
        SYSHANDLER32(SETPGID, 2)
        SYSHANDLER32(CHDIR, 1)
        SYSHANDLER32(CHROOT, 1)
        SYSHANDLER32(GETCWD, 2)
        SYSHANDLER32(READDIR, 3)
        SYSHANDLER32(READLINK, 5)
        SYSHANDLER32(GETHOSTNAME, 2)
        SYSHANDLER32(SETHOSTNAME, 2)
        SYSHANDLER32(UNAME, 1)
        SYSHANDLER64(PIPE, 1)
        SYSHANDLER32(PREAD, 5)
        SYSHANDLER32(PWRITE, 5)
        SYSHANDLER32(UNLINK, 4)
        SYSHANDLER32(RENAME, 6)
        SYSHANDLER32(EXIT_THREAD, 1)
        SYSHANDLER32(MPROTECT, 3)
        SYSHANDLER32(CREATE_THREAD, 3)
        SYSHANDLER32(MOUNT, 6)
        SYSHANDLER32(UMOUNT, 3)
        SYSHANDLER32(MKNOD, 5)
        SYSHANDLER32(STATVFS, 4)
        SYSHANDLER32(FSTATVFS, 2)
        SYSHANDLER32(FTRUNCATE, 3)
        SYSHANDLER32(GETTID, 0)
        SYSHANDLER32(GETSID, 1)
        SYSHANDLER32(GETGROUPS, 2)
        SYSHANDLER32(YIELD, 0)
        SYSHANDLER32(LINK, 6)
        SYSHANDLER32(SYMLINK, 5)
        SYSHANDLER32(CHMOD, 5)
        SYSHANDLER32(FCHMOD, 2)
        SYSHANDLER32(SETSID, 0)
        SYSHANDLER32(POLL, 4)
        SYSHANDLER32(UMASK, 1)
        SYSHANDLER32(TGKILL, 3)
        SYSHANDLER32(CHOWN, 6)
        SYSHANDLER32(SIGALTSTACK, 2)
        SYSHANDLER32(SIGSUSPEND, 1)
        SYSHANDLER32(SIGPENDING, 1)
        SYSHANDLER32(SETGROUPS, 2)
        SYSHANDLER32(PAUSE, 0)
        SYSHANDLER32(SETRESUID, 3)
        SYSHANDLER32(SETRESGID, 3)
        SYSHANDLER32(GETRESUID, 1)
        SYSHANDLER32(GETRESGID, 1)
        SYSHANDLER32(SETREUID, 2)
        SYSHANDLER32(SETREGID, 2)
        SYSHANDLER32(SETUID, 1)
        SYSHANDLER32(SETEUID, 1)
        SYSHANDLER32(SETGID, 1)
        SYSHANDLER32(SETEGID, 1)
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

void set_syscall_result(int value) {
    if (current->regs.vector == 0x20) {
        current->regs.vector = 0;
        current->regs.eax = value;
    }
}

int get_syscall_result() {
    return current->regs.eax;
}
