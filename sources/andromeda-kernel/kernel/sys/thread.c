#include "thread.h"
#include "compiler.h"
#include "cpu/gdt.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/syscall.h"
#include "util/panic.h"
#include <errno.h>

int sys_SET_TCB(uintptr_t addr) {
    current->tdata = addr;
    gdt_refresh_tdata();
    return 0;
}

int sys_EXIT_THREAD(int status) {
    if (!current->pnode.prev && !current->pnode.next) {
        ASSERT(!current->process->wa_info.si_signo);
        current->process->wa_info = (siginfo_t){
                .si_signo = SIGCHLD,
                .si_code = CLD_EXITED,
                .si_pid = getpid(),
                .si_uid = current->process->ruid,
                .si_status = status,
        };
    }

    sched_exit();
    return 0;
}

int sys_CREATE_THREAD(uintptr_t entrypoint, uintptr_t tdata, uintptr_t stack) {
    thread_t *thread;
    pid_t tid = tfork(&thread);

    thread->regs.ebp = 0;
    thread->regs.esp = stack;
    thread->regs.eip = entrypoint;
    thread->tdata = tdata;

    sched_unblock(thread);
    return tid;
}

pid_t sys_GETTID() {
    return gettid();
}

int sys_TGKILL(pid_t pid, pid_t tid, int signal) {
    if (unlikely(pid < 0)) return -EINVAL;
    if (unlikely(tid < 0)) return -EINVAL;
    if (unlikely(signal < 0) || unlikely(signal >= NSIG)) return -EINVAL;

    thread_t *thread = resolve_tid(tid);
    if (unlikely(!thread)) return -ESRCH;
    if (unlikely(proc_to_pid(thread->process) != pid)) return -ESRCH;
    if (unlikely(!can_send_signal(thread->process, signal))) return -ESRCH;

    siginfo_t info = {.si_signo = signal, .si_code = SI_USER};
    send_signal(thread->process, thread, &info, false);
    return 0;
}

static void pause_cont(void *) {
    set_syscall_result(-EINTR);
}

int sys_PAUSE() {
    sched_block(pause_cont, nullptr, true);
    return 0;
}
