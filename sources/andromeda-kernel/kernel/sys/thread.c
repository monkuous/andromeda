#include "thread.h"
#include "cpu/gdt.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "util/panic.h"

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
