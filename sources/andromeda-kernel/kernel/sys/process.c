#include "process.h"
#include "compiler.h"
#include "mem/usermem.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/syscall.h"
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

    thread_t *thread = thread_create(nullptr, nullptr);
    thread->vm->references -= 1;
    thread->vm = vm;
    thread->sigstack = current->sigstack;

    pid_t pid = pfork(thread);
    if (unlikely(pid < 0)) {
        thread_deref(thread); // this takes care of destroying the vm
        return pid;
    }

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
