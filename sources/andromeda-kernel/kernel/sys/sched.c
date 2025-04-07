#include "sched.h"
#include "proc/sched.h"

int sys_YIELD() {
    sched_yield();
    return 0;
}
