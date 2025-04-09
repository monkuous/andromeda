#include "compiler.h"
#include "fs/vfs.h"
#include "klimits.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "sys/syscall.h"
#include "util/list.h"
#include "util/panic.h"
#include <errno.h>
#include <sys/poll.h>

void fifo_init(inode_t *inode) {
    inode->fifo.buffer = vmalloc(PIPE_BUF);
}

static size_t fifo_count(fifo_state_t *state) {
    if (!state->has_data) return 0;

    if (state->read_index < state->write_index) {
        return state->write_index - state->read_index;
    }

    return (PIPE_BUF - state->write_index) + state->read_index;
}

static size_t fifo_free(fifo_state_t *state) {
    if (!state->has_data) return PIPE_BUF;

    if (state->write_index <= state->read_index) {
        return state->read_index - state->write_index;
    }

    return (PIPE_BUF - state->write_index) + state->read_index;
}

struct read_ctx {
    list_node_t node;
    thread_t *thread;
    inode_t *inode;
    void *buffer;
    size_t size;
};

struct write_ctx {
    list_node_t node;
    thread_t *thread;
    inode_t *inode;
    void *buffer;
    size_t size;
    size_t done;
};

static int read_now(inode_t *inode, void *buffer, size_t *size) {
    void *src = inode->fifo.buffer;
    size_t ri = inode->fifo.read_index;

    size_t max = *size;
    size_t cur = fifo_count(&inode->fifo);
    if (cur > max) cur = max;
    *size = cur;
    ASSERT(cur > 0);

    size_t p0 = PIPE_BUF - ri;
    if (p0 > cur) p0 = cur;

    int error = user_memcpy(buffer, src + ri, p0);
    if (unlikely(error)) return error;

    ri += p0;
    if (ri == PIPE_BUF) ri = 0;

    cur -= p0;
    if (!cur) goto exit;
    buffer += p0;

    error = user_memcpy(buffer, src, cur);
    if (unlikely(error)) return error;

    ri += cur;
    ASSERT(ri != PIPE_BUF);

exit:
    inode->fifo.read_index = ri;
    inode->fifo.has_data = ri != inode->fifo.write_index;

    list_foreach(inode->fifo.write_waiting, struct read_ctx, node, cur) {
        sched_unblock(cur->thread);
    }

    return 0;
}

static int write_now(inode_t *inode, void *buffer, size_t *size) {
    void *src = inode->fifo.buffer;
    size_t wi = inode->fifo.write_index;

    size_t max = *size;
    size_t cur = fifo_free(&inode->fifo);
    if (cur > max) cur = max;
    *size = cur;
    ASSERT(cur > 0);

    size_t p0 = PIPE_BUF - wi;
    if (p0 > cur) p0 = cur;

    int error = user_memcpy(src + wi, buffer, p0);
    if (unlikely(error)) return error;

    wi += p0;
    if (wi == PIPE_BUF) wi = 0;

    cur -= p0;
    if (!cur) goto exit;
    buffer += p0;

    error = user_memcpy(src, buffer, cur);
    if (unlikely(error)) return error;

    wi += cur;
    ASSERT(wi != PIPE_BUF);

exit:
    inode->fifo.write_index = wi;
    inode->fifo.has_data = true;

    list_foreach(inode->fifo.read_waiting, struct read_ctx, node, cur) {
        sched_unblock(cur->thread);
    }

    return 0;
}

static void send_sigpipe() {
    siginfo_t info = {
            .si_signo = SIGPIPE,
            .si_code = SI_KERNEL,
    };
    send_signal(current->process, nullptr, &info, false);
}

static void read_cont(void *ptr) {
    struct read_ctx *ctx = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else if (!fifo_count(&ctx->inode->fifo)) {
        if (ctx->inode->fifo.num_writers != 0) {
            sched_block(read_cont, ctx, true);
            return;
        }

        set_syscall_result(0);
    } else {
        int error = -read_now(ctx->inode, ctx->buffer, &ctx->size);

        if (likely(!error)) set_syscall_result(ctx->size);
        else set_syscall_result(error);
    }

    inode_deref(ctx->inode);
    list_remove(&ctx->inode->fifo.read_waiting, &ctx->node);
    vmfree(ctx, sizeof(*ctx));
}

static void write_cont(void *ptr) {
    struct write_ctx *ctx = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else if (ctx->inode->fifo.num_readers == 0) {
        set_syscall_result(-EPIPE);
        send_sigpipe();
    } else if (!fifo_free(&ctx->inode->fifo)) {
        sched_block(write_cont, ctx, true);
        return;
    } else {
        size_t cur = ctx->size;
        int error = -write_now(ctx->inode, ctx->buffer, &cur);

        if (likely(!error)) {
            ctx->done += cur;
            ctx->size -= cur;

            if (ctx->size) {
                ctx->buffer += cur;
                sched_block(write_cont, ctx, true);
                return;
            }

            set_syscall_result(ctx->done);
        } else {
            set_syscall_result(error);
        }
    }

    inode_deref(ctx->inode);
    list_remove(&ctx->inode->fifo.write_waiting, &ctx->node);
    vmfree(ctx, sizeof(*ctx));
}

static int fifo_read(file_t *self, void *buffer, size_t *size, uint64_t, bool) {
    inode_t *inode = self->inode;

    if (!fifo_count(&inode->fifo)) {
        if (!inode->fifo.num_writers) {
            *size = 0;
            return 0;
        }

        if (!(self->flags & O_NONBLOCK)) {
            struct read_ctx *ctx = vmalloc(sizeof(*ctx));
            ctx->thread = current;
            ctx->inode = inode;
            ctx->buffer = buffer;
            ctx->size = *size;
            inode_ref(inode);
            list_insert_tail(&inode->fifo.read_waiting, &ctx->node);
            sched_block(read_cont, ctx, true);
        }

        return EAGAIN;
    }

    return read_now(inode, buffer, size);
}

static int fifo_write(file_t *self, void *buffer, size_t *size, uint64_t, bool) {
    inode_t *inode = self->inode;

    if (inode->fifo.num_writers == 0) {
        send_sigpipe();
        return EPIPE;
    }

    size_t max = *size;
    size_t avail = fifo_free(&inode->fifo);
    if (avail > max) avail = max;

    if (self->flags & O_NONBLOCK) {
        if (avail == 0 || (max <= PIPE_BUF && avail < max)) return EAGAIN;
    }

    if (avail) {
        int error = write_now(inode, buffer, &avail);
        if (unlikely(error)) return error;
        buffer += avail;
        max -= avail;
    }

    if (max && !(self->flags & O_NONBLOCK)) {
        struct write_ctx *ctx = vmalloc(sizeof(*ctx));
        ctx->thread = current;
        ctx->inode = inode;
        ctx->buffer = buffer;
        ctx->size = max;
        ctx->done = avail;
        inode_ref(inode);
        list_insert_tail(&inode->fifo.write_waiting, &ctx->node);
        sched_block(write_cont, ctx, true);
        return EAGAIN;
    }

    *size = avail;
    return 0;
}

void fifo_no_readers(inode_t *inode) {
    list_foreach(inode->fifo.write_waiting, struct write_ctx, node, cur) {
        sched_unblock(cur->thread);
    }
}

void fifo_no_writers(inode_t *inode) {
    list_foreach(inode->fifo.read_waiting, struct read_ctx, node, cur) {
        sched_unblock(cur->thread);
    }
}

static int fifo_poll(file_t *self) {
    inode_t *inode = self->inode;
    int value = 0;

    if (fifo_count(&inode->fifo)) value |= POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
    if (fifo_free(&inode->fifo)) value |= POLLOUT | POLLWRNORM | POLLWRBAND;
    if (!inode->fifo.num_writers) value |= POLLHUP;

    return value;
}

static void fifo_poll_submit(file_t *self, poll_waiter_t *waiter) {
    list_insert_tail(&self->inode->fifo.poll_waiting, &waiter->node);
}

static void fifo_poll_cancel(file_t *self, poll_waiter_t *waiter) {
    list_remove(&self->inode->fifo.poll_waiting, &waiter->node);
}

const file_ops_t fifo_ops = {
        .read = fifo_read,
        .write = fifo_write,
        .poll = fifo_poll,
        .poll_cancel = fifo_poll_cancel,
        .poll_submit = fifo_poll_submit,
};

void fifo_open_read_cont(void *ptr) {
    fifo_open_wait_ctx_t *ctx = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else {
        int fd = fd_alloc();
        if (likely(fd >= 0)) fd_assoc(fd, ctx->file, ctx->fd_flags);
        set_syscall_result(fd);
    }

    list_remove(&ctx->file->inode->fifo.open_read_waiting, &ctx->node);
    file_deref(ctx->file);
    vmfree(ctx, sizeof(*ctx));
}

void fifo_open_write_cont(void *ptr) {
    fifo_open_wait_ctx_t *ctx = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else {
        int fd = fd_alloc();
        if (likely(fd >= 0)) fd_assoc(fd, ctx->file, ctx->fd_flags);
        set_syscall_result(fd);
    }

    list_remove(&ctx->file->inode->fifo.open_write_waiting, &ctx->node);
    file_deref(ctx->file);
    vmfree(ctx, sizeof(*ctx));
}
