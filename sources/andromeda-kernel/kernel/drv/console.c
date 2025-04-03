#include "console.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/list.h"
#include "util/panic.h"
#include <abi-bits/termios.h>
#include <andromeda/ioctl.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <sys/stat.h>
#include <termios.h>

// everything here is a giant TODO

static unsigned char *line_buf;
static size_t line_cap;
static size_t line_cnt;
static size_t line_len;
static list_t line_waiting;
static list_t poll_waiting;

struct console_read_op_ctx {
    list_node_t node;
    void *buf;
    size_t count;
    thread_t *thread;
};

static int do_read(void *buf, size_t *count) {
    ASSERT(line_len);

    size_t rem = *count;
    size_t tot = 0;
    int error;

    do {
        size_t cur = rem < line_len ? rem : line_len;

        error = user_memcpy(buf, line_buf, cur);
        if (unlikely(error)) break;

        memmove(line_buf, &line_buf[cur], line_cnt - cur);
        line_cnt -= cur;
        line_len -= cur;

        if (!line_len && line_cnt) {
            size_t i = 0;
            while (i < line_cnt && line_buf[i] != '\n') i++;
            if (i != line_cnt) line_len = i + 1;
        }

        tot += cur;
        buf += cur;
        rem -= cur;
    } while (rem && line_len);

    *count = tot;
    return 0;
}

static void console_read_cont(void *ptr) {
    struct console_read_op_ctx *op = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
        return;
    }

    if (!line_len) {
        sched_block(console_read_cont, op, true);
        return;
    }

    int error = do_read(op->buf, &op->count);

    if (likely(!error)) set_syscall_result(op->count);
    else set_syscall_result(-error);

    list_remove(&line_waiting, &op->node);
    vmfree(op, sizeof(*op));
}

static int console_file_read(file_t *file, void *buf, size_t *count, uint64_t, bool) {
    size_t rem = *count;
    ASSERT(rem);

    if (!line_len && (console_poll_events(), !line_len)) {
        if (!(file->flags & O_NONBLOCK)) {
            struct console_read_op_ctx *op = vmalloc(sizeof(*op));
            op->buf = buf;
            op->count = rem;
            op->thread = current;

            list_insert_tail(&line_waiting, &op->node);
            sched_block(console_read_cont, op, true);
        }

        return EAGAIN;
    }

    return do_read(buf, count);
}

static int console_file_write(file_t *, void *buf, size_t *count, uint64_t, bool) {
    size_t rem = *count;
    unsigned char buffer[1024];

    while (rem) {
        size_t cur = rem < sizeof(buffer) ? rem : sizeof(buffer);

        int error = user_memcpy(buffer, buf, cur);
        if (unlikely(error)) return error;

        console_write(buffer, cur);

        buf += cur;
        rem -= cur;
    }

    return 0;
}

static int console_ioctl(file_t *, unsigned long request, void *arg) {
    switch (request) {
    case TIOCGWINSZ: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(struct winsize));
        if (unlikely(error)) return error;

        struct winsize value = {
                .ws_row = 25,
                .ws_col = 80,
        };
        error = -user_memcpy(arg, &value, sizeof(value));
        if (unlikely(error)) return error;

        return 0;
    }
    case TCGETS:
    case TCSETS:
    case TCSETSF:
    case TCSETSW: return -ENOSYS;
    default: return -ENOTTY;
    }
}

static int console_poll(file_t *) {
    console_poll_events();

    int flags = POLLOUT | POLLWRNORM | POLLWRBAND;
    if (line_len) flags |= POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
    return flags;
}

static void console_poll_submit(file_t *, poll_waiter_t *waiter) {
    list_insert_tail(&poll_waiting, &waiter->node);
}

static void console_poll_cancel(file_t *, poll_waiter_t *waiter) {
    list_remove(&poll_waiting, &waiter->node);
}

static const file_ops_t console_file_ops = {
        .read = console_file_read,
        .write = console_file_write,
        .ioctl = console_ioctl,
        .poll = console_poll,
        .poll_submit = console_poll_submit,
        .poll_cancel = console_poll_cancel,
};

int open_console(uint32_t minor, file_t *file, int) {
    if (minor) return ENXIO;

    file->ops = &console_file_ops;

    return 0;
}

static void allocassoc_or_die(int fd, file_t *file, int flags) {
    int error = fd_allocassoc(fd, file, flags);
    if (unlikely(error)) panic("failed to open standard fd %d (%d)", fd, error);
}

void init_console() {
    int error = vfs_mknod(nullptr, "/dev/tty", 8, S_IFCHR | 0666, DEVICE_ID(DRIVER_CONSOLE, 0));
    if (unlikely(error)) panic("failed to create /dev/tty (%d)", error);

    // set up stdin, stdout, and stderr
    {
        file_t *file;
        error = vfs_open(&file, nullptr, "/dev/tty", 8, O_RDWR, 0);
        if (unlikely(error)) panic("failed to open console (%d)", error);

        allocassoc_or_die(2, file, 0);
        allocassoc_or_die(1, file, 0);
        allocassoc_or_die(0, file, 0);
        file_deref(file);
    }
}

static size_t echo_count;

static bool can_read_char() {
    regs_t regs = {.eax = 0x100};
    intcall(0x16, &regs);
    return !(regs.eflags & 0x40);
}

static unsigned char read_char() {
    regs_t regs = (regs_t){};
    intcall(0x16, &regs);
    return regs.eax & 0xff;
}

static void write_char(unsigned char c) {
    regs_t regs = {.eax = 0xe00 | c};
    intcall(0x10, &regs);
}

static void print_single(unsigned char c) {
    if (c == '\n') write_char('\r');
    write_char(c);
}

void console_write(const void *buf, size_t len) {
    if (!len) return;

    const unsigned char *data = buf;

    do {
        print_single(*data++);
    } while (--len);

    echo_count = 0;
}

void console_poll_events() {
    bool had_line = line_len != 0;

    for (;;) {
        if (!can_read_char()) break;

        unsigned char c = read_char();
        if (c == '\r') c = '\n';

        switch (c) {
        case '\b':
            if (echo_count) {
                write_char('\b');
                write_char(' ');
                write_char('\b');
                echo_count -= 1;
            }

            if (line_len != line_cnt) {
                line_cnt -= 1;
            }
            break;
        case '\n':
        case 0x20 ... 0x7e:
            if (line_cnt >= line_cap) {
                size_t new_cap = line_cap ? line_cap * 2 : 8;
                void *new_buf = vmalloc(new_cap);
                memcpy(new_buf, line_buf, line_cap);
                vmfree(line_buf, line_cap);
                line_buf = new_buf;
                line_cap = new_cap;
            }

            line_buf[line_cnt++] = c;
            print_single(c);

            if (c == '\n') {
                if (!line_len) line_len = line_cnt;
                echo_count = 0;
            } else {
                echo_count += 1;
            }
            break;
        }
    }

    if (!had_line && line_len) {
        list_foreach(line_waiting, struct console_read_op_ctx, node, cur) {
            sched_unblock(cur->thread);
        }

        list_foreach(poll_waiting, poll_waiter_t, node, cur) {
            sched_unblock(cur->thread);
        }
    }
}
