#pragma once

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

int sys_OPEN(int dirfd, uintptr_t path, size_t length, int flags, mode_t mode);
off_t sys_SEEK(int fd, unsigned long offset_low, unsigned long offset_high, int whence);
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
ssize_t sys_READDIR(int fd, uintptr_t buf, size_t max_size);
ssize_t sys_READLINK(int dirfd, uintptr_t path, size_t length, uintptr_t buffer, size_t size);
int64_t sys_PIPE(int flags);
ssize_t sys_PREAD(int fd, uintptr_t buf, ssize_t count, uint32_t off_low, uint32_t off_high);
ssize_t sys_PWRITE(int fd, uintptr_t buf, ssize_t count, uint32_t off_low, uint32_t off_high);
int sys_UNLINK(int dirfd, uintptr_t path, size_t length, int flags);
int sys_RENAME(int srcdirfd, uintptr_t srcpath, size_t srclength, int dstdirfd, uintptr_t dstpath, size_t dstlength);
int sys_MOUNT(int srcdirfd, uintptr_t srcpath, size_t srclength, int dirfd, uintptr_t path, size_t length);
int sys_UMOUNT(int dirfd, uintptr_t path, size_t length);
int sys_MKNOD(int dirfd, uintptr_t path, size_t length, mode_t mode, dev_t device);
int sys_STATVFS(int dirfd, uintptr_t path, size_t length, uintptr_t buffer);
int sys_FSTATVFS(int fd, uintptr_t buffer);
int sys_FTRUNCATE(int fd, uint32_t size_low, uint32_t size_high);
int sys_LINK(int tdirfd, uintptr_t tpath, size_t tlength, int ldirfd, uintptr_t lpath, int flags);
int sys_SYMLINK(int dirfd, uintptr_t path, size_t length, uintptr_t target, size_t tlen);
int sys_CHMOD(int dirfd, uintptr_t path, size_t length, mode_t mode, int flags);
int sys_FCHMOD(int fd, mode_t mode);
int sys_POLL(uintptr_t fds, size_t count, uintptr_t timeout, uintptr_t sigmask);
mode_t sys_UMASK(mode_t mode);
int sys_CHOWN(int dirfd, uintptr_t path, size_t length, uid_t uid, gid_t gid, int flags);

