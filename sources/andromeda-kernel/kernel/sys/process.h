#pragma once

#include <stdint.h>
#include <sys/types.h>

int sys_EXIT(int status);
uid_t sys_GETUID();
gid_t sys_GETGID();
uid_t sys_GETEUID();
gid_t sys_GETEGID();
pid_t sys_GETPID();
pid_t sys_GETPPID();
pid_t sys_GETPGID(pid_t pid);
int sys_SIGPROCMASK(int how, uintptr_t set, uintptr_t oset);
int sys_SIGACTION(int sig, uintptr_t act, uintptr_t oact);
int sys_SIGRETURN();
pid_t sys_FORK();
pid_t sys_PWAIT(pid_t pid, int flags, uintptr_t info);
int sys_KILL(pid_t pid, int sig);
int sys_SETPGID(pid_t pid, pid_t pgid);
