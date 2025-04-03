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
int sys_STAT(int dirfd, uintptr_t path, size_t length, int flags, uintptr_t buffer);
int sys_FSTAT(int fd, uintptr_t buffer);
int sys_PSELECT(
        int nfds,
        uintptr_t readfds,
        uintptr_t writefds,
        uintptr_t errorfds,
        uintptr_t timeout,
        uintptr_t sigmask
);
int sys_ACCESS(int dirfd, uintptr_t path, size_t length, int amode, int flags);
int sys_CHDIR(int fd);
int sys_CHROOT(int fd);
ssize_t sys_GETCWD(uintptr_t buf, size_t size);
