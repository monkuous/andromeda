#pragma once

#include <stdint.h>

int sys_SET_TCB(uintptr_t addr);
int sys_EXIT_THREAD(int status);
int sys_CREATE_THREAD(uintptr_t entrypoint, uintptr_t tdata, uintptr_t stack);
