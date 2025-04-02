#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int sys_OPEN(int dirfd, uintptr_t path, size_t length, int flags, mode_t mode);
off_t sys_SEEK(int fd, off_t offset, int whence);
ssize_t sys_READ(int fd, uintptr_t buf, ssize_t count);
int sys_CLOSE(int fd);
ssize_t sys_WRITE(int fd, uintptr_t buf, ssize_t count);
int sys_IOCTL(int fd, unsigned long request, uintptr_t arg);
int sys_FCNTL(int fd, int cmd, uintptr_t arg);
int sys_DUP(int fd, int flags);
int sys_DUP2(int fd, int flags, int new_fd);
