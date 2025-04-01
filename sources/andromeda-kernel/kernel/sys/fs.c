#include "fs.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "sys/syscall.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>

int sys_OPEN(int dirfd, uintptr_t path, size_t length, int flags, mode_t mode) {
    int ret = -verify_pointer(path, length);
    if (unlikely(ret)) return ret;

    void *buf = vmalloc(length);
    ret = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(ret)) goto exit;

    file_t *rel;

    if (dirfd != AT_FDCWD) {
        ret = -fd_lookup(&rel, dirfd);
        if (unlikely(ret)) goto exit;
    } else {
        rel = nullptr;
    }

    ret = fd_alloc();
    if (unlikely(ret < 0)) goto exit;

    file_t *file;
    int error = vfs_open(&file, rel, buf, length, flags, mode);
    if (unlikely(error)) {
        fd_free(ret);
        ret = -error;
        goto exit;
    }

    fd_assoc(ret, file, (flags & O_CLOEXEC) ? FD_CLOEXEC : 0);
    file_deref(file);
exit:
    vmfree(buf, length);
    return ret;
}

off_t sys_SEEK(int fd, off_t offset, int whence) {
    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    offset = vfs_seek(file, offset, whence);
    file_deref(file);
    return offset;
}

ssize_t sys_READ(int fd, uintptr_t buf, ssize_t count) {
    if (unlikely(count < 0)) return -EINVAL;

    int error = -verify_pointer(buf, count);
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    count = vfs_read(file, (void *)buf, count);
    file_deref(file);
    return count;
}

int sys_CLOSE(int fd) {
    return -fd_free_checked(fd);
}

ssize_t sys_WRITE(int fd, uintptr_t buf, ssize_t count) {
    if (unlikely(count < 0)) return -EINVAL;

    int error = -verify_pointer(buf, count);
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    count = vfs_write(file, (const void *)buf, count);
    file_deref(file);
    return count;
}
