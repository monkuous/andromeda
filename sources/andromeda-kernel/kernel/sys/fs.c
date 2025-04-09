#include "fs.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/detect.h"
#include "fs/fifo.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/list.h"
#include <andromeda/string.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>

#define OPEN_FD_FLAGS_MASK O_CLOEXEC

static int get_fd_flags(int value) {
    int flags = 0;
    if (value & O_CLOEXEC) flags |= FD_CLOEXEC;
    return flags;
}

static int get_at_file(file_t **out, int fd) {
    if (fd != AT_FDCWD) {
        return fd_lookup(out, fd);
    } else {
        *out = nullptr;
        return 0;
    }
}

int sys_OPEN(int dirfd, uintptr_t path, size_t length, int flags, mode_t mode) {
    int ret = -verify_pointer(path, length);
    if (unlikely(ret)) return ret;

    void *buf = vmalloc(length);
    ret = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(ret)) goto exit;

    file_t *rel;
    ret = -get_at_file(&rel, dirfd);
    if (unlikely(ret)) goto exit;

    ret = fd_alloc();
    if (unlikely(ret < 0)) goto exit2;

    file_t *file;
    int error = -vfs_open(&file, rel, buf, length, flags, mode);
    if (unlikely(error)) {
        fd_free(ret);
        ret = error;
        goto exit2;
    }

    if (!(flags & O_NONBLOCK) && S_ISFIFO(file->inode->mode)) {
        if ((flags & O_ACCMODE) == O_RDONLY && file->inode->fifo.num_writers == 0) {
            fifo_open_wait_ctx_t *ctx = vmalloc(sizeof(*ctx));
            ctx->thread = current;
            ctx->file = file;
            ctx->fd_flags = get_fd_flags(flags);
            list_insert_tail(&file->inode->fifo.open_read_waiting, &ctx->node);
            fd_free(ret);
            sched_block(fifo_open_read_cont, ctx, true);
            ret = -EAGAIN;
            goto exit2;
        }

        if ((flags & O_ACCMODE) == O_WRONLY && file->inode->fifo.num_readers == 0) {
            fifo_open_wait_ctx_t *ctx = vmalloc(sizeof(*ctx));
            ctx->thread = current;
            ctx->file = file;
            ctx->fd_flags = get_fd_flags(flags);
            list_insert_tail(&file->inode->fifo.open_write_waiting, &ctx->node);
            fd_free(ret);
            sched_block(fifo_open_write_cont, ctx, true);
            ret = -EAGAIN;
            goto exit2;
        }
    }

    fd_assoc(ret, file, get_fd_flags(flags));
    file_deref(file);
exit2:
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return ret;
}

off_t sys_SEEK(int fd, unsigned long offset_low, unsigned long offset_high, int whence) {
    off_t offset = ((uint64_t)offset_high << 32) | offset_low;

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

int sys_IOCTL(int fd, unsigned long request, uintptr_t arg) {
    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = vfs_ioctl(file, request, (void *)arg);
    file_deref(file);
    return error;
}

int sys_FCNTL(int fd, int cmd, uintptr_t arg) {
    return fd_fcntl(fd, cmd, arg);
}

int sys_DUP(int fd, int flags) {
    if (unlikely(flags & ~OPEN_FD_FLAGS_MASK)) return -EINVAL;

    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    int res = fd_alloc();
    if (unlikely(res < 0)) {
        file_deref(file);
        return res;
    }

    fd_assoc(res, file, get_fd_flags(flags));
    file_deref(file);
    return res;
}

int sys_DUP2(int fd, int flags, int new_fd) {
    if (unlikely(flags & ~OPEN_FD_FLAGS_MASK)) return -EINVAL;

    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    if (fd != new_fd) {
        error = -fd_allocassoc(new_fd, file, get_fd_flags(flags));
    }

    file_deref(file);
    return error;
}

int sys_STAT(int dirfd, uintptr_t path, size_t length, int flags, uintptr_t buffer) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    error = -verify_pointer(buffer, sizeof(struct stat));
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_stat(rel, buf, length, (struct stat *)buffer, flags);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_FSTAT(int fd, uintptr_t buffer) {
    int error = -verify_pointer(buffer, sizeof(struct stat));
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -vfs_fstat(file, (struct stat *)buffer);
    file_deref(file);
    return error;
}

typedef struct {
    poll_waiter_t base;
    sigset_t orig_mask;
    size_t buf_size;
    size_t count;
    file_t **files;
    uint32_t *rbits;
    uint32_t *wbits;
    uint32_t *ebits;
    uintptr_t rfds;
    uintptr_t wfds;
    uintptr_t efds;
    size_t input_size;
} pselect_ctx_t;

static void pselect_ctx_free(pselect_ctx_t *ctx) {
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->files[i]) file_deref(ctx->files[i]);
    }

    vmfree(ctx, ctx->buf_size);
}

static bool should_check(uint32_t *bitmap, size_t index) {
    if (!bitmap) return false;
    return bitmap[index / 32] & (1ul << (index % 32));
}

static void bm_set(uint32_t *bitmap, size_t index) {
    bitmap[index / 32] |= (1ul << (index % 32));
}

static void bm_clear(uint32_t *bitmap, size_t index) {
    bitmap[index / 32] &= ~(1ul << (index % 32));
}

static void clear_earlier_bits(uint32_t *bitmap, size_t index) {
    size_t idx = index / 32;
    bitmap[idx] &= 0xffffffff << (index % 32);
    memset(bitmap, 0, idx * sizeof(*bitmap));
}

static void clear_later_bits(uint32_t *bitmap, size_t index) {
    size_t idx = index / 32;
    size_t off = index % 32;
    if (off == 31) return;
    bitmap[idx] &= ~(0xffffffff << (off + 1));
}

static bool process_bitmap(int pval, int mask, uint32_t *bitmap, size_t index, bool writing) {
    if (pval & mask) {
        if (should_check(bitmap, index)) {
            bm_set(bitmap, index);
            if (!writing) clear_earlier_bits(bitmap, index);
            return true;
        }
    } else if (writing && bitmap) {
        bm_clear(bitmap, index);
    }

    return false;
}

static int pselect_run(pselect_ctx_t *ctx) {
    bool writing = false;
    int count = 0;

    for (size_t i = 0; i < ctx->count; i++) {
        file_t *file = ctx->files[i];
        if (!file) continue;

        // we can't skip files without poll, otherwise their bits might not get cleared
        int pval = file->ops->poll ? file->ops->poll(file) : 0;
        if (unlikely(pval < 0)) return pval;

        if (process_bitmap(pval, POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI, ctx->rbits, i, writing)) {
            writing = true;
            count += 1;
        }

        if (process_bitmap(pval, POLLOUT | POLLWRNORM | POLLWRBAND | POLLERR, ctx->wbits, i, writing)) {
            writing = true;
            count += 1;
        }

        if (process_bitmap(pval, POLLERR, ctx->ebits, i, writing)) {
            writing = true;
            count += 1;
        }
    }

    if (writing) {
        if (ctx->rbits) {
            clear_later_bits(ctx->rbits, ctx->count - 1);
            int error = -user_memcpy((void *)ctx->rfds, ctx->rbits, ctx->input_size);
            if (unlikely(error)) return error;
        }

        if (ctx->wbits) {
            clear_later_bits(ctx->wbits, ctx->count - 1);
            int error = -user_memcpy((void *)ctx->wfds, ctx->wbits, ctx->input_size);
            if (unlikely(error)) return error;
        }

        if (ctx->ebits) {
            clear_later_bits(ctx->ebits, ctx->count - 1);
            int error = -user_memcpy((void *)ctx->efds, ctx->ebits, ctx->input_size);
            if (unlikely(error)) return error;
        }
    }

    return count;
}

static void pselect_cont(void *ptr) {
    pselect_ctx_t *ctx = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else {
        int count = pselect_run(ctx);
        if (count == 0) {
            sched_block(pselect_cont, ctx, true);
            return;
        }

        set_syscall_result(count);
    }

    for (size_t i = 0; i < ctx->count; i++) {
        file_t *file = ctx->files[i];

        if (file && file->ops->poll) {
            file->ops->poll_cancel(file, &ctx->base);
        }
    }

    current->signal_mask = ctx->orig_mask;
    pselect_ctx_free(ctx);
}

int sys_PSELECT(
        int nfds,
        uintptr_t readfds,
        uintptr_t writefds,
        uintptr_t errorfds,
        uintptr_t timeout,
        uintptr_t sigmask
) {
    if (unlikely(nfds < 0) || unlikely(nfds > FD_SETSIZE)) return -EINVAL;

    int error;
    size_t input_size = (nfds + 7) / 8;
    size_t bitmap_size = (nfds + 31) / 32 * sizeof(uint32_t);
    size_t rsize = 0;
    size_t wsize = 0;
    size_t esize = 0;
    sigset_t mask;
    struct timespec time;

    if (readfds) {
        error = -verify_pointer(readfds, input_size);
        if (unlikely(error)) return error;
        rsize = bitmap_size;
    }

    if (writefds) {
        error = -verify_pointer(writefds, input_size);
        if (unlikely(error)) return error;
        wsize = bitmap_size;
    }

    if (errorfds) {
        error = -verify_pointer(errorfds, input_size);
        if (unlikely(error)) return error;
        esize = bitmap_size;
    }

    if (sigmask) {
        error = -verify_pointer(sigmask, sizeof(mask));
        if (unlikely(error)) return error;

        error = -user_memcpy(&mask, (const void *)sigmask, sizeof(mask));
        if (unlikely(error)) return error;

        sigset_sanitize(&mask);
    } else {
        memset(&mask, 0, sizeof(mask));
    }

    if (timeout) {
        error = -verify_pointer(timeout, sizeof(time));
        if (unlikely(error)) return error;

        error = -user_memcpy(&time, (const void *)timeout, sizeof(time));
        if (unlikely(error)) return error;
    }

    size_t fls_offs = sizeof(pselect_ctx_t);
    size_t fls_size = sizeof(file_t *) * nfds;

    size_t roffs = fls_offs + fls_size;
    size_t woffs = roffs + rsize;
    size_t eoffs = woffs + wsize;

    size_t buf_size = eoffs + esize;
    void *buf = vmalloc(buf_size);
    memset(buf, 0, buf_size);

    pselect_ctx_t *ctx = buf;
    ctx->base.thread = current;
    ctx->orig_mask = current->signal_mask;
    ctx->buf_size = buf_size;
    ctx->files = buf + fls_offs;
    ctx->rbits = rsize ? buf + roffs : nullptr;
    ctx->wbits = wsize ? buf + woffs : nullptr;
    ctx->ebits = esize ? buf + eoffs : nullptr;
    ctx->rfds = readfds;
    ctx->wfds = writefds;
    ctx->efds = errorfds;
    ctx->input_size = input_size;

    if (ctx->rbits) {
        error = -user_memcpy(ctx->rbits, (const void *)readfds, input_size);
        if (unlikely(error)) goto exit;
    }

    if (ctx->wbits) {
        error = -user_memcpy(ctx->wbits, (const void *)writefds, input_size);
        if (unlikely(error)) goto exit;
    }

    if (ctx->ebits) {
        error = -user_memcpy(ctx->ebits, (const void *)errorfds, input_size);
        if (unlikely(error)) goto exit;
    }

    for (size_t i = 0; i < (unsigned)nfds; i++) {
        if (should_check(ctx->rbits, i) || should_check(ctx->wbits, i) || should_check(ctx->ebits, i)) {
            error = -fd_lookup(&ctx->files[i], i);
            if (unlikely(error)) goto exit;
            ctx->count = i + 1;
        }
    }

    current->signal_mask = mask;
    error = pselect_run(ctx);

    if (error == 0 && (timeout == 0 || time.tv_sec != 0 || time.tv_nsec != 0)) {
        for (size_t i = 0; i < ctx->count; i++) {
            file_t *file = ctx->files[i];

            if (file && file->ops->poll) {
                file->ops->poll_submit(file, &ctx->base);
            }
        }

        // TODO: Timeout
        sched_block(pselect_cont, ctx, true);
        return 0;
    }

exit:
    current->signal_mask = ctx->orig_mask;
    pselect_ctx_free(ctx);
    return error;
}

int sys_ACCESS(int dirfd, uintptr_t path, size_t length, int amode, int flags) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_access(rel, buf, length, amode, flags);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_CHDIR(int fd) {
    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -vfs_chdir(file);
    file_deref(file);
    return error;
}

int sys_CHROOT(int fd) {
    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -vfs_chroot(file);
    file_deref(file);
    return error;
}

ssize_t sys_GETCWD(uintptr_t buf, size_t size) {
    int error = -verify_pointer(buf, size);
    if (unlikely(error)) return error;
    if (unlikely(!size)) return -EINVAL;
    if (size > 0x7fffffff) size = 0x7fffffff;

    void *ptr;
    size_t len = vfs_alloc_path(&ptr, current->process->cwd->path);
    error = -user_memcpy((void *)buf, ptr, len < size ? len : size);
    vmfree(ptr, len);
    if (unlikely(error)) return error;

    return len;
}

ssize_t sys_READDIR(int fd, uintptr_t buf, size_t max_size) {
    int error = -verify_pointer(buf, max_size);
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    if (max_size > 0x7fffffff) max_size = 0x7fffffff;

    ssize_t ret = vfs_readdir(file, (void *)buf, max_size);
    file_deref(file);
    return ret;
}

ssize_t sys_READLINK(int dirfd, uintptr_t path, size_t length, uintptr_t buffer, size_t size) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    error = -verify_pointer(buffer, size);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto error;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto error;

    if (size > 0x7fffffff) size = 0x7fffffff;

    error = -vfs_readlink(rel, buf, length, (void *)buffer, &size);
    if (rel) file_deref(rel);
    if (unlikely(error)) goto error;

    vmfree(buf, length);
    return size;
error:
    vmfree(buf, length);
    return error;
}

int64_t sys_PIPE(int flags) {
    if (unlikely(flags & ~(O_CLOEXEC | O_NONBLOCK))) return -EINVAL;

    int rfd = fd_alloc();
    if (unlikely(rfd < 0)) return rfd;

    int wfd = fd_alloc();
    if (unlikely(wfd < 0)) {
        fd_free(rfd);
        return wfd;
    }

    inode_t *inode = create_anonymous_inode(S_IFIFO | 0600, 0);
    file_t *rfile, *wfile;

    int error = -open_inode(&rfile, nullptr, inode, flags | O_RDONLY, nullptr);
    if (unlikely(error)) {
        inode_deref(inode);
        fd_free(wfd);
        fd_free(rfd);
        return error;
    }

    error = -open_inode(&wfile, nullptr, inode, flags | O_WRONLY, nullptr);
    inode_deref(inode);
    if (unlikely(error)) {
        file_deref(rfile);
        fd_free(wfd);
        fd_free(rfd);
        return error;
    }

    fd_assoc(rfd, rfile, get_fd_flags(flags));
    fd_assoc(wfd, wfile, get_fd_flags(flags));
    file_deref(rfile);
    file_deref(wfile);

    return ((int64_t)rfd << 32) | wfd;
}

ssize_t sys_PREAD(int fd, uintptr_t buf, ssize_t count, uint32_t off_low, uint32_t off_high) {
    if (unlikely(count < 0)) return -EINVAL;
    if (unlikely(off_high & 0x80000000)) return -EINVAL;

    int error = -verify_pointer(buf, count);
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    count = vfs_pread(file, (void *)buf, count, ((uint64_t)off_high << 32) | off_low);
    file_deref(file);
    return count;
}

ssize_t sys_PWRITE(int fd, uintptr_t buf, ssize_t count, uint32_t off_low, uint32_t off_high) {
    if (unlikely(count < 0)) return -EINVAL;
    if (unlikely(off_high & 0x80000000)) return -EINVAL;

    int error = -verify_pointer(buf, count);
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    count = vfs_pwrite(file, (const void *)buf, count, ((uint64_t)off_high << 32) | off_low);
    file_deref(file);
    return count;
}

int sys_UNLINK(int dirfd, uintptr_t path, size_t length, int flags) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_unlink(rel, buf, length, flags);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_RENAME(int srcdirfd, uintptr_t srcpath, size_t srclength, int dstdirfd, uintptr_t dstpath, size_t dstlength) {
    int error = -verify_pointer(srcpath, srclength);
    if (unlikely(error)) return error;

    error = -verify_pointer(dstpath, dstlength);
    if (unlikely(error)) return error;

    void *srcbuf = vmalloc(srclength);
    error = -user_memcpy(srcbuf, (const void *)srcpath, srclength);
    if (unlikely(error)) goto exit;

    void *dstbuf = vmalloc(dstlength);
    error = -user_memcpy(dstbuf, (const void *)dstpath, dstlength);
    if (unlikely(error)) goto exit2;

    file_t *srcrel;
    error = -get_at_file(&srcrel, srcdirfd);
    if (unlikely(error)) goto exit2;

    file_t *dstrel;
    error = -get_at_file(&dstrel, dstdirfd);
    if (unlikely(error)) goto exit3;

    error = -vfs_rename(srcrel, srcbuf, srclength, dstrel, dstbuf, dstlength);

    if (dstrel) file_deref(dstrel);
exit3:
    if (srcrel) file_deref(srcrel);
exit2:
    vmfree(dstbuf, dstlength);
exit:
    vmfree(srcbuf, srclength);
    return error;
}

int sys_MOUNT(int srcdirfd, uintptr_t srcpath, size_t srclength, int dirfd, uintptr_t path, size_t length) {
    int error;

    if (srclength) {
        error = -verify_pointer(srcpath, srclength);
        if (unlikely(error)) return error;
    }

    error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *srcbuf = srclength ? vmalloc(srclength) : nullptr;
    error = -user_memcpy(srcbuf, (const void *)srcpath, srclength);
    if (unlikely(error)) goto exit;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit2;

    file_t *srcrel;

    if (srclength) {
        error = -get_at_file(&srcrel, srcdirfd);
        if (unlikely(error)) goto exit2;
    } else {
        srcrel = nullptr;
    }

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit3;

    if (srclength) {
        struct stat stat;
        error = -vfs_stat(srcrel, srcbuf, srclength, &stat, 0);
        if (unlikely(error)) goto exit4;

        if (!S_ISBLK(stat.st_mode)) {
            error = -ENOTBLK;
            goto exit4;
        }

        bdev_t *bdev = resolve_bdev(stat.st_rdev);
        if (unlikely(!bdev)) {
            error = -ENXIO;
            goto exit4;
        }

        error = -vfs_mount(rel, buf, length, fsdetect, bdev);
    } else {
        struct ramfs_create_ctx ctx = {.mode = 0755};
        error = -vfs_mount(rel, buf, length, ramfs_create, &ctx);
    }

exit4:
    if (rel) file_deref(rel);
exit3:
    if (srcrel) file_deref(srcrel);
exit2:
    vmfree(buf, length);
exit:
    vmfree(srcbuf, srclength);
    return error;
}

int sys_UMOUNT(int dirfd, uintptr_t path, size_t length) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_unmount(rel, buf, length);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_MKNOD(int dirfd, uintptr_t path, size_t length, mode_t mode, dev_t device) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_mknod(rel, buf, length, mode, device);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_STATVFS(int dirfd, uintptr_t path, size_t length, uintptr_t buffer) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    error = -verify_pointer(buffer, sizeof(struct statvfs));
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_statvfs(rel, buf, length, (struct statvfs *)buffer);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_FSTATVFS(int fd, uintptr_t buffer) {
    int error = -verify_pointer(buffer, sizeof(struct statvfs));
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -vfs_fstatvfs(file, (struct statvfs *)buffer);
    file_deref(file);
    return error;
}

int sys_FTRUNCATE(int fd, uint32_t size_low, uint32_t size_high) {
    off_t size = ((uint64_t)size_high << 32) | size_low;

    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -vfs_ftruncate(file, size);
    file_deref(file);
    return error;
}

int sys_LINK(int tdirfd, uintptr_t tpath, size_t tlength, int ldirfd, uintptr_t lpath, int flags) {
    int error = -verify_pointer(tpath, tlength);
    if (unlikely(error)) return error;

    error = -verify_pointer(lpath, sizeof(andromeda_tagged_string_t));
    if (unlikely(error)) return error;

    andromeda_tagged_string_t link_path;
    error = -user_memcpy(&link_path, (const void *)lpath, sizeof(link_path));
    if (unlikely(error)) return error;

    error = -verify_pointer((uintptr_t)link_path.data, link_path.length);
    if (unlikely(error)) return error;

    void *tbuf = vmalloc(tlength);
    error = -user_memcpy(tbuf, (const void *)tpath, tlength);
    if (unlikely(error)) goto exit;

    void *lbuf = vmalloc(link_path.length);
    error = -user_memcpy(lbuf, link_path.data, link_path.length);
    if (unlikely(error)) goto exit2;

    file_t *trel;
    error = -get_at_file(&trel, tdirfd);
    if (unlikely(error)) goto exit2;

    file_t *lrel;
    error = -get_at_file(&lrel, ldirfd);
    if (unlikely(error)) goto exit3;

    error = -vfs_link(lrel, lbuf, link_path.length, trel, tbuf, tlength, flags);

    if (lrel) file_deref(lrel);
exit3:
    if (trel) file_deref(trel);
exit2:
    vmfree(lbuf, tlength);
exit:
    vmfree(tbuf, tlength);
    return error;
}

int sys_SYMLINK(int dirfd, uintptr_t path, size_t length, uintptr_t tpath, size_t tlength) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    error = -verify_pointer(tpath, tlength);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    void *tbuf = vmalloc(tlength);
    error = -user_memcpy(tbuf, (const void *)tpath, tlength);
    if (unlikely(error)) goto exit2;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit2;

    error = -vfs_symlink(rel, buf, length, tbuf, tlength);

    if (rel) file_deref(rel);
exit2:
    vmfree(tbuf, tlength);
exit:
    vmfree(buf, length);
    return error;
}

int sys_CHMOD(int dirfd, uintptr_t path, size_t length, mode_t mode, int flags) {
    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_chmod(rel, buf, length, mode, flags);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}

int sys_FCHMOD(int fd, mode_t mode) {
    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -vfs_fchmod(file, mode);
    file_deref(file);
    return error;
}

struct poll_ctx {
    poll_waiter_t base;
    uintptr_t output;
    struct pollfd *fds;
    file_t **files;
    size_t count;
    size_t bufsz;
    sigset_t mask;
};

static int run_poll(struct poll_ctx *ctx) {
    int count = 0;

    for (size_t i = 0; i < ctx->count; i++) {
        file_t *file = ctx->files[i];
        if (!file || !file->ops->poll) continue;

        struct pollfd *fd = &ctx->fds[i];
        fd->revents = file->ops->poll(file) & (fd->events | POLLERR | POLLHUP);

        if (fd->revents) {
            count += 1;
        }
    }

    int error = -user_memcpy((void *)ctx->output, ctx->fds, ctx->count * sizeof(*ctx->fds));
    if (unlikely(error)) return error;

    return count;
}

static void poll_cleanup(struct poll_ctx *ctx) {
    for (size_t i = 0; i < ctx->count; i++) {
        if (ctx->files[i]) file_deref(ctx->files[i]);
    }

    vmfree(ctx, ctx->bufsz);
}

static void poll_cont(void *ptr) {
    struct poll_ctx *ctx = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else {
        int count = run_poll(ctx);
        if (count == 0) {
            sched_block(poll_cont, ctx, true);
            return;
        }

        set_syscall_result(count);
    }

    for (size_t i = 0; i < ctx->count; i++) {
        file_t *file = ctx->files[i];

        if (file && file->ops->poll) {
            file->ops->poll_cancel(file, &ctx->base);
        }
    }

    poll_cleanup(ctx);
}

int sys_POLL(uintptr_t fds, size_t count, uintptr_t timeout, uintptr_t sigmask) {
    struct timespec tmspec;
    sigset_t smset;

    size_t fds_size = count * sizeof(struct pollfd);
    int error = -verify_pointer(fds, fds_size);
    if (unlikely(error)) return error;

    if (timeout) {
        error = -verify_pointer(timeout, sizeof(tmspec));
        if (unlikely(error)) return error;

        error = -user_memcpy(&tmspec, (const void *)timeout, sizeof(tmspec));
        if (unlikely(error)) return error;
    }

    if (sigmask) {
        error = -verify_pointer(sigmask, sizeof(smset));
        if (unlikely(error)) return error;

        error = -user_memcpy(&smset, (const void *)sigmask, sizeof(smset));
        if (unlikely(error)) return error;
        sigset_sanitize(&smset);
    }

    size_t fds_offs = (sizeof(struct poll_ctx) + (alignof(struct pollfd) - 1)) & ~(alignof(struct pollfd) - 1);
    size_t fls_offs = (fds_offs + fds_size + (alignof(file_t *) - 1)) & ~(alignof(file_t *) - 1);
    size_t fls_size = count * sizeof(file_t *);
    size_t buf_size = fls_offs + fls_size;

    void *buffer = vmalloc(buf_size);
    memset(buffer, 0, buf_size);

    struct poll_ctx *ctx = buffer;
    ctx->base.thread = current;
    ctx->output = fds;
    ctx->fds = buffer + fds_offs;
    ctx->files = buffer + fls_offs;
    ctx->count = count;
    ctx->bufsz = buf_size;
    ctx->mask = current->signal_mask;

    error = -user_memcpy(ctx->fds, (const void *)fds, fds_size);
    if (unlikely(error)) goto exit;

    for (size_t i = 0; i < ctx->count; i++) {
        int fd = ctx->fds[i].fd;
        ctx->fds[i].revents = 0;
        if (fd < 0) continue;

        file_t *file;
        int error = -fd_lookup(&file, fd);

        if (unlikely(error)) {
            ctx->files[i] = nullptr;
            ctx->fds[i].revents |= POLLNVAL;
            continue;
        }

        ctx->files[i] = file;
    }

    if (sigmask) current->signal_mask = smset;

    error = run_poll(ctx);

    if (error == 0 && (!timeout || (tmspec.tv_sec == 0 && tmspec.tv_nsec == 0))) {
        for (size_t i = 0; i < ctx->count; i++) {
            file_t *file = ctx->files[i];

            if (file && file->ops->poll) {
                file->ops->poll_submit(file, &ctx->base);
            }
        }

        // TODO: Timeout
        sched_block(poll_cont, ctx, true);
        return 0;
    }

exit:
    current->signal_mask = ctx->mask;
    poll_cleanup(ctx);
    return error;
}

mode_t sys_UMASK(mode_t mode) {
    return vfs_umask(mode);
}

int sys_CHOWN(int dirfd, uintptr_t path, size_t length, uid_t uid, gid_t gid, int flags) {
    if (flags & AT_EMPTY_PATH) {
        file_t *file;
        int error = -fd_lookup(&file, dirfd);
        if (unlikely(error)) return error;

        error = -vfs_fchown(file, uid, gid);
        file_deref(file);
        return error;
    }

    int error = -verify_pointer(path, length);
    if (unlikely(error)) return error;

    void *buf = vmalloc(length);
    error = -user_memcpy(buf, (const void *)path, length);
    if (unlikely(error)) goto exit;

    file_t *rel;
    error = -get_at_file(&rel, dirfd);
    if (unlikely(error)) goto exit;

    error = -vfs_chown(rel, buf, length, uid, gid, flags);
    if (rel) file_deref(rel);
exit:
    vmfree(buf, length);
    return error;
}
