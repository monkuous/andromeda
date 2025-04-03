#include "thread.h"
#include "cpu/gdt.h"
#include "proc/sched.h"

int sys_SET_TCB(uintptr_t addr) {
    current->tdata = addr;
    gdt_refresh_tdata();
    return 0;
}
