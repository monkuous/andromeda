#include "fs.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "sys/syscall.h"
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

    fd_assoc(ret, file, get_fd_flags(flags));
    file_deref(file);
exit2:
    if (rel) file_deref(rel);
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

int sys_IOCTL(int fd, unsigned long request, uintptr_t arg) {
    file_t *file;
    int error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    return vfs_ioctl(file, request, (void *)arg);
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

    return -vfs_fstat(file, (struct stat *)buffer);
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
        if (count == 0) return;
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
        if (unlikely(error)) goto cleanup;
    }

    if (ctx->wbits) {
        error = -user_memcpy(ctx->wbits, (const void *)writefds, input_size);
        if (unlikely(error)) goto cleanup;
    }

    if (ctx->ebits) {
        error = -user_memcpy(ctx->ebits, (const void *)errorfds, input_size);
        if (unlikely(error)) goto cleanup;
    }

    for (size_t i = 0; i < (unsigned)nfds; i++) {
        if (should_check(ctx->rbits, i) || should_check(ctx->wbits, i) || should_check(ctx->ebits, i)) {
            error = -fd_lookup(&ctx->files[i], i);
            if (unlikely(error)) goto cleanup;
            ctx->count = i + 1;
        }
    }

    int count = pselect_run(ctx);

    if (count == 0 && (timeout == 0 || time.tv_sec != 0 || time.tv_nsec != 0)) {
        for (size_t i = 0; i < ctx->count; i++) {
            file_t *file = ctx->files[i];

            if (file && file->ops->poll) {
                file->ops->poll_submit(file, &ctx->base);
            }
        }

        current->signal_mask = mask;
        // TODO: Timeout
        sched_block(pselect_cont, ctx, true);
    } else {
        pselect_ctx_free(ctx);
    }

    return count;
cleanup:
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
