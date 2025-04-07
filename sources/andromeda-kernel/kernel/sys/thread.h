#pragma once

#include <stdint.h>
#include <sys/types.h>

int sys_SET_TCB(uintptr_t addr);
int sys_EXIT_THREAD(int status);
int sys_CREATE_THREAD(uintptr_t entrypoint, uintptr_t tdata, uintptr_t stack);
pid_t sys_GETTID();
int sys_TGKILL(pid_t pid, pid_t tid, int signal);
int sys_PAUSE();
