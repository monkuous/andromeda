#include "console.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "mem/vmem.h"
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

#define COLUMNS 80
#define LINES 25
#define CURSOR_CHAR 0xdb

static volatile uint16_t *video_memory;
static struct {
    uint16_t value;
    short queue_idx;
} vidmem_buffer[COLUMNS * LINES];
static struct {
    uint16_t value;
    short vidmem_idx;
} vidmem_queue[COLUMNS * LINES];
static int queue_count;

static int cur_x;
static int cur_y;
static int prev_x;
static int prev_y;
static uint16_t cur_cover;
static bool have_cursor;
static bool prev_cursor;
static uint16_t attr_mask = 0x700;

// from https://en.wikipedia.org/wiki/Code_page_437
// skips over 0x20..0x7e, which are identical in cp437 and unicode
static const uint16_t cp437_to_unicode[0x100 - (0x7f - 0x20)] = {
        0x20,   0x263a, 0x263b, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25d8, 0x25cb, 0x25d9, 0x2642, 0x2640, 0x266a,
        0x266b, 0x263c, 0x25ba, 0x25c4, 0x2195, 0x203c, 0xb6,   0xa7,   0x25ac, 0x21a8, 0x2191, 0x2193, 0x2192, 0x2190,
        0x221f, 0x2194, 0x25b2, 0x25bc, 0x2302, 0xc7,   0xfc,   0xe9,   0xe2,   0xe4,   0xe0,   0xe5,   0xe7,   0xea,
        0xeb,   0xe8,   0xef,   0xee,   0xec,   0xc4,   0xc5,   0xc9,   0xe6,   0xc6,   0xf4,   0xf6,   0xf2,   0xfb,
        0xf9,   0xff,   0xd6,   0xdc,   0xa2,   0xa3,   0xa5,   0x20a7, 0x192,  0xe1,   0xed,   0xf3,   0xfa,   0xf1,
        0xd1,   0xaa,   0xba,   0xbf,   0x2310, 0xac,   0xbd,   0xbc,   0xa1,   0xab,   0xbb,   0x2591, 0x2592, 0x2593,
        0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514,
        0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c,
        0x2567, 0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584,
        0x258c, 0x2590, 0x2580, 0x3b1,  0xdf,   0x393,  0x3c0,  0x3a3,  0x3c3,  0xb5,   0x3c4,  0x3a6,  0x398,  0x3a9,
        0x3b4,  0x221e, 0x3c6,  0x3b5,  0x2229, 0x2261, 0xb1,   0x2265, 0x2264, 0x2320, 0x2321, 0xf7,   0x2248, 0xb0,
        0x2219, 0xb7,   0x221a, 0x207f, 0xb2,   0x25a0, 0x20
};

static uint8_t unicode_to_cp437(uint32_t unicode) {
    if (likely(unicode >= 0x20 && unicode <= 0x7e)) return unicode;

    for (unsigned i = 0; i < sizeof(cp437_to_unicode) / sizeof(*cp437_to_unicode); i++) {
        if (cp437_to_unicode[i] == unicode) {
            if (i >= 0x20) i += 0x7f - 0x20;
            return i;
        }
    }

    return 0x3f;
}

static uint16_t vidmem_read(int x, int y) {
    int idx = y * COLUMNS + x;
    int qi = vidmem_buffer[idx].queue_idx - 1;

    if (qi >= 0) {
        return vidmem_queue[qi].value;
    }

    return vidmem_buffer[idx].value;
}

static void vidmem_write(int x, int y, uint16_t value) {
    int idx = y * COLUMNS + x;
    int qi = vidmem_buffer[idx].queue_idx - 1;

    if (qi < 0) {
        if (value == vidmem_buffer[idx].value) return;
        qi = queue_count++;
        vidmem_buffer[idx].queue_idx = qi + 1;
        vidmem_queue[qi].vidmem_idx = idx;
    }

    vidmem_queue[qi].value = value;
}

static void vidmem_flush() {
    for (int i = 0; i < queue_count; i++) {
        uint16_t val = vidmem_queue[i].value;
        int idx = vidmem_queue[i].vidmem_idx;

        if (val != vidmem_buffer[idx].value) {
            vidmem_buffer[idx].value = val;
            video_memory[idx] = val;
        }

        vidmem_buffer[idx].queue_idx = 0;
    }

    queue_count = 0;
}

static void set_cp437(int x, int y, uint8_t value) {
    if (!prev_cursor || x != prev_x || y != prev_y) vidmem_write(x, y, attr_mask | value);
    else cur_cover = attr_mask | value;
}

static void set_code_point(int x, int y, uint32_t cp) {
    set_cp437(x, y, unicode_to_cp437(cp));
}

static void update_cursor() {
    if (have_cursor) {
        if (prev_cursor) {
            if (cur_x == prev_x && cur_y == prev_y) return;
            vidmem_write(prev_x, prev_y, cur_cover);
        } else {
            prev_cursor = true;
        }

        prev_x = cur_x;
        prev_y = cur_y;

        cur_cover = vidmem_read(cur_x, cur_y);
        vidmem_write(cur_x, cur_y, attr_mask | CURSOR_CHAR);
    } else if (prev_cursor) {
        prev_cursor = false;
        vidmem_write(prev_x, prev_y, cur_cover);
    }
}

static void write_code_point(uint32_t cp) {
    if (!video_memory) return;

    switch (cp) {
    case '\b':
        cur_x -= 1;

        if (cur_x < 0) {
            cur_x = 0;

            if (cur_y > 0) cur_y -= 1;
        }
        break;
    case '\t': cur_x = (cur_x + 8) & ~7; break;
    case '\n': cur_y += 1; break;
    case '\r': cur_x = 0; break;
    default: set_code_point(cur_x++, cur_y, cp); break;
    }

    if (cur_x >= COLUMNS) {
        cur_x = 0;
        cur_y += 1;
    }

    if (cur_y >= LINES) {
        for (int y = 1; y < LINES; y++) {
            for (int x = 0; x < COLUMNS; x++) {
                vidmem_write(x, y - 1, vidmem_read(x, y));
            }
        }

        for (int x = 0; x < COLUMNS; x++) {
            vidmem_write(x, LINES - 1, attr_mask | 0x20);
        }

        cur_y -= 1;
        prev_y -= 1;
        if (prev_y < 0) prev_cursor = false;
    }
}

static uint32_t utf8_cur;
static uint32_t utf8_min;
static unsigned utf8_rem;

#define UTF8_ERROR 0xfffd

static void write_char(unsigned char c) {
again:
    if (!utf8_rem) {
        if ((c & 0x80) == 0) {
            write_code_point(c);
            return;
        } else if ((c & 0xe0) == 0xc0) {
            utf8_min = 0x80;
            utf8_rem = 1;
        } else if ((c & 0xf0) == 0xe0) {
            utf8_min = 0x800;
            utf8_rem = 2;
        } else if ((c & 0xf8) == 0xf0) {
            utf8_min = 0x10000;
            utf8_rem = 3;
        } else {
            write_code_point(UTF8_ERROR);
            return;
        }

        utf8_cur = c;
        return;
    }

    if ((c & 0xc0) != 0x80) {
        write_code_point(UTF8_ERROR);
        utf8_rem = 0;
        goto again;
    }

    utf8_cur <<= 6;
    utf8_cur |= c & 0x3f;

    if (--utf8_rem == 0) {
        write_code_point(utf8_cur >= utf8_min ? utf8_cur : UTF8_ERROR);
    }
}

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
    } else if (!line_len) {
        sched_block(console_read_cont, op, true);
        return;
    } else {
        int error = do_read(op->buf, &op->count);

        if (likely(!error)) set_syscall_result(op->count);
        else set_syscall_result(-error);
    }

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

void init_console_early() {
    // ensure video mode is 3 (80x25 color text)
    regs_t regs = (regs_t){.eax = 3};
    intcall(0x10, &regs);

    // disable cursor
    regs = (regs_t){.eax = 0x100, .ecx = 0x2000};
    intcall(0x10, &regs);

    size_t map_size = (COLUMNS * LINES * 2 + PAGE_MASK) & ~PAGE_MASK;
    uintptr_t vaddr = vmem_alloc(map_size);
    pmap_map(vaddr, 0xb8000, map_size, PMAP_WRITABLE);
    video_memory = (void *)vaddr;

    update_cursor();
}

void console_set_cursor(bool cursor) {
    have_cursor = cursor;
    update_cursor();
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

    update_cursor();
    vidmem_flush();
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

    update_cursor();
    vidmem_flush();

    if (!had_line && line_len) {
        list_foreach(line_waiting, struct console_read_op_ctx, node, cur) {
            sched_unblock(cur->thread);
        }

        list_foreach(poll_waiting, poll_waiter_t, node, cur) {
            sched_unblock(cur->thread);
        }
    }
}
