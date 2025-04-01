#include "thread.h"
#include "cpu/gdt.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "util/panic.h"
#include <signal.h> /* IWYU pragma: keep */

int sys_SET_TCB(uintptr_t addr) {
    current->tdata = addr;
    gdt_refresh_tdata();
    return 0;
}

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
