#include "process.h"
#include "compiler.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/list.h"
#include "util/panic.h"
#include <errno.h>

int sys_EXIT(int status) {
    kill_other_threads();

    ASSERT(!current->process->wa_info.si_signo);
    current->process->wa_info = (siginfo_t){
            .si_signo = SIGCHLD,
            .si_code = CLD_EXITED,
            .si_pid = getpid(),
            .si_uid = current->process->ruid,
            .si_status = status,
    };
    sched_exit();
    return 0;
}

uid_t sys_GETUID() {
    return current->process->ruid;
}

gid_t sys_GETGID() {
    return current->process->rgid;
}

uid_t sys_GETEUID() {
    return current->process->euid;
}

gid_t sys_GETEGID() {
    return current->process->egid;
}

pid_t sys_GETPID() {
    return getpid();
}

pid_t sys_GETPPID() {
    return getppid();
}

pid_t sys_GETPGID(pid_t pid) {
    return getpgid(pid);
}

int sys_SIGPROCMASK(int how, uintptr_t set, uintptr_t oset) {
    int error;

    if (oset) {
        error = -verify_pointer(oset, sizeof(sigset_t));
        if (unlikely(error)) return error;

        error = -user_memcpy((void *)oset, &current->signal_mask, sizeof(current->signal_mask));
        if (unlikely(error)) return error;
    }

    if (set) {
        error = -verify_pointer(set, sizeof(sigset_t));
        if (unlikely(error)) return error;

        sigset_t value;
        error = -user_memcpy(&value, (const void *)set, sizeof(value));
        if (unlikely(error)) return error;

        sigset_sanitize(&value);

        switch (how) {
        case SIG_BLOCK: sigset_join(&current->signal_mask, &value); break;
        case SIG_SETMASK: current->signal_mask = value; break;
        case SIG_UNBLOCK: sigset_cmask(&current->signal_mask, &value); break;
        default: return -EINVAL;
        }
    }

    return 0;
}

int sys_SIGACTION(int sig, uintptr_t act, uintptr_t oact) {
    if (unlikely(sig <= 0 || sig >= NSIG)) return -EINVAL;
    if (unlikely(sig == SIGKILL || sig == SIGSTOP)) return -EINVAL;

    int error;

    if (oact) {
        error = -verify_pointer(oact, sizeof(struct sigaction));
        if (unlikely(error)) return error;

        error = -user_memcpy(
                (void *)oact,
                &current->process->signal_handlers[sig],
                sizeof(*current->process->signal_handlers)
        );
        if (unlikely(error)) return error;
    }

    if (act) {
        error = -verify_pointer(act, sizeof(struct sigaction));
        if (unlikely(error)) return error;

        error = -user_memcpy(
                &current->process->signal_handlers[sig],
                (const void *)act,
                sizeof(*current->process->signal_handlers)
        );
        if (unlikely(error)) return error;

        if (sig == SIGCHLD && current->process->signal_handlers[sig].sa_handler == SIG_IGN) {
            current->process->signal_handlers[sig].sa_flags |= SA_NOCLDWAIT;
        }
    }

    return 0;
}

pid_t sys_FORK() {
    vm_t *vm = vm_clone();

    thread_t *thread;
    pid_t pid = pfork(&thread);
    if (unlikely(pid < 0)) return pid;

    thread->vm->references -= 1;
    thread->vm = vm;
    thread->sigstack = current->sigstack;

    thread->regs.eax = 0; // set syscall return value in child
    sched_unblock(thread);

    return pid;
}

static void sys_pwait_cont(pid_t pid, siginfo_t *info, void *info_out) {
    if (likely(pid >= 0)) {
        int error = -user_memcpy(info_out, info, sizeof(*info));
        if (unlikely(error)) pid = error;
    }

    set_syscall_result(pid);
}

pid_t sys_PWAIT(pid_t pid, int flags, uintptr_t info) {
    int error = -verify_pointer(info, sizeof(siginfo_t));
    if (unlikely(error)) return error;

    pid = pwait(pid, flags, sys_pwait_cont, (void *)info);

    if (pid > 0) {
        // the continuation was called immediately
        return get_syscall_result();
    }

    return pid;
}

int sys_SIGRETURN() {
    int error = -return_from_signal();
    if (unlikely(error)) set_syscall_result(error);
    return error;
}

int sys_KILL(pid_t pid, int sig) {
    return -proc_sendsig(pid, sig);
}

int sys_SETPGID(pid_t pid, pid_t pgid) {
    return -setpgid(pid, pgid);
}

pid_t sys_GETSID(pid_t pid) {
    return getsid(pid);
}

int sys_GETGROUPS(uintptr_t list, size_t size) {
    int error = -verify_pointer(list, size * sizeof(gid_t));
    if (unlikely(error)) return error;

    return proc_getgroups(size, (gid_t *)list);
}

pid_t sys_SETSID() {
    return setsid();
}

int sys_SIGALTSTACK(uintptr_t stack, uintptr_t old) {
    int error;

    if (old) {
        error = -verify_pointer(old, sizeof(current->sigstack));
        if (unlikely(error)) return error;

        error = -user_memcpy((void *)old, &current->sigstack, sizeof(current->sigstack));
        if (unlikely(error)) return error;
    }

    if (stack) {
        error = -verify_pointer(stack, sizeof(current->sigstack));
        if (unlikely(error)) return error;

        error = -user_memcpy(&current->sigstack, (const void *)stack, sizeof(current->sigstack));
        if (unlikely(error)) return error;
    }

    return 0;
}

static void sigsusp_cont(void *ptr) {
    struct sigsuspend_ctx *ctx = ptr;

    if (will_trigger_signal()) {
        current->signal_mask = ctx->old_mask;
        list_remove(&current->process->sigsuspends, &ctx->node);
        vmfree(ctx, sizeof(*ctx));
        set_syscall_result(-EINTR);
    } else {
        sched_block(sigsusp_cont, ctx, true);
    }
}

int sys_SIGSUSPEND(uintptr_t mask) {
    int error = -verify_pointer(mask, sizeof(sigset_t));
    if (unlikely(error)) return error;

    sigset_t new_mask;
    error = -user_memcpy(&new_mask, (const void *)mask, sizeof(new_mask));
    if (unlikely(error)) return error;
    sigset_sanitize(&new_mask);

    sigset_t old_mask = current->signal_mask;
    current->signal_mask = new_mask;

    if (!will_trigger_signal()) {
        struct sigsuspend_ctx *ctx = vmalloc(sizeof(*ctx));
        memset(ctx, 0, sizeof(*ctx));

        ctx->thread = current;
        ctx->old_mask = old_mask;

        list_insert_tail(&current->process->sigsuspends, &ctx->node);
        sched_block(sigsusp_cont, ctx, true);
    } else {
        current->signal_mask = old_mask;
    }

    return -EINTR;
}

int sys_SIGPENDING(uintptr_t out) {
    int error = -verify_pointer(out, sizeof(sigset_t));
    if (unlikely(error)) return error;

    sigset_t set = {};

    for (unsigned i = 0; i < NSIG; i++) {
        if (sigset_get(&current->signal_mask, i) && is_pending(i)) {
            sigset_set(&set, i);
        }
    }

    return -user_memcpy((void *)out, &set, sizeof(set));
}

int sys_SETGROUPS(uintptr_t list, size_t size) {
    return -proc_setgroups(size, (const gid_t *)list);
}

int sys_SETRESUID(uid_t ruid, uid_t euid, uid_t suid) {
    return -setresuid(ruid, euid, suid);
}

int sys_SETRESGID(gid_t rgid, gid_t egid, gid_t sgid) {
    return -setresgid(rgid, egid, sgid);
}

int sys_GETRESUID(uintptr_t uids) {
    uid_t buf[3];

    int error = -verify_pointer(uids, sizeof(buf));
    if (unlikely(error)) return error;

    buf[0] = current->process->ruid;
    buf[1] = current->process->euid;
    buf[2] = current->process->suid;

    return -user_memcpy((void *)uids, buf, sizeof(buf));
}

int sys_GETRESGID(uintptr_t gids) {
    gid_t buf[3];

    int error = -verify_pointer(gids, sizeof(buf));
    if (unlikely(error)) return error;

    buf[0] = current->process->rgid;
    buf[1] = current->process->egid;
    buf[2] = current->process->sgid;

    return -user_memcpy((void *)gids, buf, sizeof(buf));
}

int sys_SETREUID(uintptr_t ruid, uintptr_t euid) {
    return -setreuid(ruid, euid);
}

int sys_SETREGID(uintptr_t rgid, uintptr_t egid) {
    return -setregid(rgid, egid);
}

int sys_SETUID(uid_t uid) {
    return -setuid(uid);
}

int sys_SETEUID(uid_t euid) {
    return -seteuid(euid);
}

int sys_SETGID(gid_t gid) {
    return -setgid(gid);
}

int sys_SETEGID(gid_t egid) {
    return -setegid(egid);
}
