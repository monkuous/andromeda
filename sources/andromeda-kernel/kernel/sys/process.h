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
pid_t sys_GETSID(pid_t pid);
int sys_GETGROUPS(uintptr_t list, size_t size);
pid_t sys_SETSID();
int sys_SIGALTSTACK(uintptr_t stack, uintptr_t old);
int sys_SIGSUSPEND(uintptr_t mask);
int sys_SIGPENDING(uintptr_t out);
int sys_SETGROUPS(uintptr_t list, size_t size);
int sys_SETRESUID(uid_t ruid, uid_t euid, uid_t suid);
int sys_SETRESGID(gid_t rgid, gid_t egid, gid_t sgid);
int sys_GETRESUID(uintptr_t uids);
int sys_GETRESGID(uintptr_t gids);
int sys_SETREUID(uintptr_t ruid, uintptr_t euid);
int sys_SETREGID(uintptr_t rgid, uintptr_t egid);
int sys_SETUID(uid_t uid);
int sys_SETEUID(uid_t euid);
int sys_SETGID(gid_t gid);
int sys_SETEGID(gid_t egid);
