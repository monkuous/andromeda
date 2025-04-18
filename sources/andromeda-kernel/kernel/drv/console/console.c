#include "../console.h"
#include "compiler.h"
#include "drv/console/screen.h"
#include "drv/console/vt.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/print.h"
#include <andromeda/ioctl.h>
#include <errno.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>

static unsigned char *input_buf;
static size_t input_cap;
static size_t input_cnt;
static size_t line_len;
static bool input_enabled = true;

static list_t input_waiting;
static list_t output_waiting;
static list_t poll_waiting;

static struct termios termios = {
        .c_iflag = IUTF8 | IMAXBEL | IXON | ICRNL | BRKINT,
        .c_oflag = ONLCR | OPOST,
        .c_cflag = HUPCL | CREAD | CS8 | B38400,
        .c_lflag = IEXTEN | ECHOKE | ECHOCTL | ECHOK | ECHOE | ECHO | ICANON | ISIG,
        .c_line = 0,
        .c_cc =
                {
                        [VINTR] = 0x03,  /* ^C */
                        [VQUIT] = 0x1c,  /* ^\ */
                        [VERASE] = 0x7f, /* Backspace */
                        [VKILL] = 0x15,  /* ^U */
                        [VEOF] = 0x04,   /* ^D */
                        [VMIN] = 1,
                        [VSTART] = 0x11,   /* ^Q */
                        [VSTOP] = 0x13,    /* ^S */
                        [VSUSP] = 0x1a,    /* ^Z */
                        [VREPRINT] = 0x12, /* ^R */
                        [VDISCARD] = 0x0f, /* ^O */
                        [VWERASE] = 0x17,  /* ^W */
                        [VLNEXT] = 0x16,   /* ^V */
                },
        .ibaud = B38400,
        .obaud = B38400,
};

static bool output_enabled = true;
static struct winsize window_size = {
        .ws_col = SCREEN_WIDTH,
        .ws_row = SCREEN_HEIGHT,
};

static prgroup_t *tty_group;
static session_t *tty_session;
static size_t num_file_descs;

static size_t echo_count;

struct console_read_op_ctx {
    list_node_t node;
    void *buf;
    size_t count;
    thread_t *thread;
};

static size_t input_available() {
    if (!input_enabled) return 0;

    if (termios.c_lflag & ICANON) {
        return line_len;
    } else if (input_cnt < termios.c_cc[VMIN]) {
        return 0;
    } else {
        return input_cnt;
    }
}

static bool is_eol(unsigned char c) {
    if (c == '\n') return true;
    if (termios.c_cc[VEOL] && c == termios.c_cc[VEOL]) return true;
    if (termios.c_cc[VEOF] && c == termios.c_cc[VEOF]) return true;
    return false;
}

static void rescan_line_len() {
    if (input_cnt) {
        size_t i = 0;
        while (i < input_cnt && !is_eol(input_buf[i])) i++;
        if (i != input_cnt) line_len = i + 1;
    } else {
        line_len = 0;
    }
}

static int do_read(void *buf, size_t *count) {
    size_t rem = *count;
    size_t max = input_available();
    size_t tot = 0;
    int error;

    ASSERT(max);

    while (rem) {
        size_t cur = rem < max ? rem : max;

        error = user_memcpy(buf, input_buf, cur);
        if (unlikely(error)) break;

        memmove(input_buf, &input_buf[cur], input_cnt - cur);
        input_cnt -= cur;
        max -= cur;

        tot += cur;
        buf += cur;
        rem -= cur;
        max -= cur;

        if (termios.c_lflag & ICANON) {
            ASSERT(cur <= line_len);
            line_len -= cur;

            if (!line_len) {
                rescan_line_len();
                break;
            }
        }
    }

    *count = tot;
    return 0;
}

static void console_read_cont(void *ptr) {
    struct console_read_op_ctx *op = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else if (!input_available()) {
        sched_block(console_read_cont, op, true);
        return;
    } else {
        int error = do_read(op->buf, &op->count);

        if (likely(!error)) set_syscall_result(op->count);
        else set_syscall_result(-error);
    }

    list_remove(&input_waiting, &op->node);
    vmfree(op, sizeof(*op));
}

static int check_read() {
    if (tty_session == current->process->group->session && tty_group != current->process->group) {
        if (is_masked_or_ignored(SIGTTIN)) return EIO;
        if (!current->process->group->orphan_inhibitors) return EIO;

        siginfo_t info = {.si_signo = SIGTTIN, .si_code = SI_KERNEL};
        group_signal(current->process->group, &info);
        return EINTR;
    }

    return 0;
}

static int console_file_read(file_t *file, void *buf, size_t *count, uint64_t, bool) {
    int error = check_read();
    if (unlikely(error)) return error;

    if (!input_available() && (console_poll_events(), !input_available())) {
        if (!(termios.c_lflag & ICANON) && !(termios.c_cc[VMIN] | termios.c_cc[VTIME])) {
            *count = 0;
            return 0;
        }

        if (!(file->flags & O_NONBLOCK)) {
            struct console_read_op_ctx *op = vmalloc(sizeof(*op));
            op->buf = buf;
            op->count = *count;
            op->thread = current;

            list_insert_tail(&input_waiting, &op->node);
            sched_block(console_read_cont, op, true);
        }

        return EAGAIN;
    }

    return do_read(buf, count);
}

struct console_write_op_ctx {
    list_node_t node;
    void *buf;
    size_t count;
    thread_t *thread;
};

static int do_write(void *buf, size_t *count) {
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

    screen_flush();
    return 0;
}

static void console_write_cont(void *ptr) {
    struct console_read_op_ctx *op = ptr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else if (!output_enabled) {
        sched_block(console_write_cont, op, true);
        return;
    } else {
        int error = do_write(op->buf, &op->count);

        if (likely(!error)) set_syscall_result(op->count);
        else set_syscall_result(-error);
    }

    list_remove(&output_waiting, &op->node);
    vmfree(op, sizeof(*op));
}

static int check_write(bool ignore_tostop) {
    if (current->process->group->session == tty_session && current->process->group != tty_group) {
        if (!ignore_tostop && !(termios.c_lflag & TOSTOP)) return 0;
        if (is_masked_or_ignored(SIGTTOU)) return 0;
        if (!current->process->group->orphan_inhibitors) return EIO;

        siginfo_t info = {.si_signo = SIGTTOU, .si_code = SI_KERNEL};
        group_signal(current->process->group, &info);
        return EINTR;
    }

    return 0;
}

static int console_file_write(file_t *file, void *buf, size_t *count, uint64_t, bool) {
    int error = check_write(false);
    if (unlikely(error)) return error;

    if (!output_enabled && (console_poll_events(), !output_enabled)) {
        if (!(file->flags & O_NONBLOCK)) {
            struct console_write_op_ctx *op = vmalloc(sizeof(*op));
            op->buf = buf;
            op->count = *count;
            op->thread = current;

            list_insert_tail(&output_waiting, &op->node);
            sched_block(console_write_cont, op, true);
        }

        return EAGAIN;
    }

    return do_write(buf, count);
}

static void on_change_foreground() {
}

static void on_change_controller() {
}

static void maybe_wake_readers() {
    if (!input_available()) return;
    if (!(termios.c_lflag & ICANON) && input_cnt < termios.c_cc[VMIN]) return;

    list_foreach(input_waiting, struct console_read_op_ctx, node, cur) {
        sched_unblock(cur->thread);
    }

    list_foreach(poll_waiting, poll_waiter_t, node, cur) {
        sched_unblock(cur->thread);
    }
}

static void restart_output() {
    output_enabled = true;

    list_foreach(output_waiting, struct console_write_op_ctx, node, cur) {
        sched_unblock(cur->thread);
    }
}

static int console_ioctl(file_t *, unsigned long request, void *arg) {
    switch (request) {
    case TIOCGWINSZ: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(window_size));
        if (unlikely(error)) return error;

        return -user_memcpy(arg, &window_size, sizeof(window_size));
    }
    case TIOCSWINSZ: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(window_size));
        if (unlikely(error)) return error;

        struct winsize inwinsz;
        error = -user_memcpy(&inwinsz, arg, sizeof(window_size));
        if (unlikely(error)) return error;

        if (inwinsz.ws_col < 1 || inwinsz.ws_row < 1) return -EINVAL;

        bool changed = window_size.ws_col != inwinsz.ws_col || window_size.ws_row != inwinsz.ws_row;
        bool changed_px = window_size.ws_xpixel != inwinsz.ws_xpixel || window_size.ws_ypixel != inwinsz.ws_ypixel;
        window_size = inwinsz;

        if (tty_group && (changed || changed_px)) {
            siginfo_t info = {.si_signo = SIGWINCH, .si_code = SI_KERNEL};
            group_signal(tty_group, &info);
        }

        return 0;
    }
    case TCGETS: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(termios));
        if (unlikely(error)) return error;

        return -user_memcpy(arg, &termios, sizeof(termios));
    }
    case TCSETS:
    case TCSETSF:
    case TCSETSW: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(termios));
        if (unlikely(error)) return error;

        struct termios new_termios;
        error = -user_memcpy(&new_termios, arg, sizeof(new_termios));
        if (unlikely(error)) return error;

        error = -check_write(false);
        if (unlikely(error)) return error;

        termios = new_termios;
        if (request == TCSETSF) input_cnt = line_len = echo_count = 0;

        if (termios.c_lflag & ICANON) rescan_line_len();

        if (!(termios.c_lflag & IXON)) restart_output();

        maybe_wake_readers();
        return 0;
    }
    case TIOCGPGRP: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(pid_t));
        if (unlikely(error)) return error;

        if (!tty_session || tty_session != current->process->group->session) return -ENOTTY;

        pid_t pgid = tty_group ? get_pgid(tty_group) : INT_MAX;
        return -user_memcpy(arg, &pgid, sizeof(pgid));
    }
    case TIOCSPGRP: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(pid_t));
        if (unlikely(error)) return error;

        pid_t pgid;
        error = -user_memcpy(&pgid, arg, sizeof(pgid));
        if (unlikely(error)) return error;
        if (unlikely(pgid < 0)) return -EINVAL;

        prgroup_t *group = resolve_pgid(pgid);
        if (unlikely(!group)) return -ESRCH;
        if (unlikely(group->session != current->process->group->session)) return -EPERM;

        if (!tty_session || tty_session != group->session) return -ENOTTY;

        if (check_write(true)) {
            if (!current->process->group->orphan_inhibitors) return -EIO;

            siginfo_t info = {.si_signo = SIGTTOU, .si_code = SI_KERNEL};
            send_signal(current->process, nullptr, &info, false);
            return -EINTR;
        }

        if (tty_group != group) {
            console_disconnect_from_group();
            tty_group = group;
            on_change_foreground();
        }

        return 0;
    }
    case TIOCGSID: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(pid_t));
        if (unlikely(error)) return error;

        if (!tty_session || tty_session != current->process->group->session) return -ENOTTY;

        pid_t sid = get_sid(tty_session);
        return -user_memcpy(arg, &sid, sizeof(sid));
    }
    case TIOCSCTTY: {
        if ((uintptr_t)arg >= 2) return -EINVAL;
        if (!is_session_leader(current->process)) return -EPERM;
        if (tty_session == current->process->group->session) return 0;

        if (tty_session) {
            if (current->process->euid || !arg) return -EPERM;
            console_disconnect_from_session(false);
        }

        tty_group = current->process->group;
        tty_session = tty_group->session;
        current->process->owns_tty = true;
        on_change_controller();
        return 0;
    }
    case TCXONC:
        switch ((uintptr_t)arg) {
        case TCOOFF: output_enabled = false; break;
        case TCOON: restart_output(); break;
        case TCIOFF: input_enabled = false; break;
        case TCION:
            input_enabled = true;
            maybe_wake_readers();
            break;
        default: return -EINVAL;
        }
        return 0;
    case TCFLSH:
        switch ((uintptr_t)arg) {
        case TCIFLUSH:
        case TCIOFLUSH: input_cnt = line_len = echo_count = 0; break;
        case TCOFLUSH: break;
        default: return -EINVAL;
        }
        return 0;
    case TCSBRK: return 0;
    case IOCTL_GET_MODIFIER_STATE: {
        regs_t regs = {.eax = 0x200};
        intcall(0x16, &regs);

        int flags = 0;

        if (regs.eax & 1) flags |= MODIFIER_RIGHT_SHIFT;
        if (regs.eax & 2) flags |= MODIFIER_LEFT_SHIFT;
        if (regs.eax & 4) flags |= MODIFIER_CONTROL;
        if (regs.eax & 8) flags |= MODIFIER_ALT;
        if (regs.eax & 16) flags |= MODIFIER_SCROLL_LOCK;
        if (regs.eax & 32) flags |= MODIFIER_NUM_LOCK;
        if (regs.eax & 64) flags |= MODIFIER_CAPS_LOCK;
        if (regs.eax & 128) flags |= MODIFIER_INSERT;

        return flags;
    }
    default: printk("console: unknown ioctl 0x%x with arg %p\n", request, arg); return -ENOTTY;
    }
}

static int console_poll(file_t *) {
    console_poll_events();

    int flags = POLLOUT | POLLWRNORM | POLLWRBAND;
    if (input_available()) flags |= POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI;
    return flags;
}

static void console_poll_submit(file_t *, poll_waiter_t *waiter) {
    list_insert_tail(&poll_waiting, &waiter->node);
}

static void console_poll_cancel(file_t *, poll_waiter_t *waiter) {
    list_remove(&poll_waiting, &waiter->node);
}

static void console_file_free(file_t *) {
    if (--num_file_descs == 0 && tty_session) {
        console_disconnect_from_session(false);
    }
}

static const file_ops_t console_file_ops = {
        .free = console_file_free,
        .read = console_file_read,
        .write = console_file_write,
        .ioctl = console_ioctl,
        .poll = console_poll,
        .poll_submit = console_poll_submit,
        .poll_cancel = console_poll_cancel,
};

int open_console(uint32_t minor, file_t *file, int flags) {
    if (minor) return ENXIO;

    file->ops = &console_file_ops;

    if (!(flags & O_NOCTTY) && !tty_session && is_session_leader(current->process)) {
        tty_group = current->process->group;
        tty_session = tty_group->session;

        current->process->owns_tty = true;
        tty_group->foreground = true;
        on_change_controller();
    }

    num_file_descs++;
    return 0;
}

static void allocassoc_or_die(int fd, file_t *file, int flags) {
    int error = fd_allocassoc(fd, file, flags);
    if (unlikely(error)) panic("failed to open standard fd %d (%d)", fd, error);
}

void init_console_early() {
    vt_init();
    screen_flush();
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

static void write_byte(uint8_t byte) {
    if (termios.c_oflag & OPOST) {
        switch (byte) {
        case '\n':
            if (termios.c_oflag & ONLCR) {
                if (vt_state.x != 0 || !(termios.c_oflag & ONOCR)) vt_write_byte('\r');
            }
            break;
        case '\r':
            if (termios.c_oflag & OCRNL) byte = '\n';
            break;
        case 'a' ... 'z':
            if (termios.c_oflag & OLCUC) byte &= ~0x20;
            break;
        }

        if (byte == '\r') {
            if (vt_state.x == 0 && (termios.c_oflag & ONOCR)) return;
        }
    }

    vt_write_byte(byte);
}

void console_write(const void *buf, size_t len) {
    if (!len) return;

    const unsigned char *data = buf;

    do {
        write_byte(*data++);
    } while (--len);

    echo_count = 0;
}

static void signal_after_char(int sig) {
    if (!tty_group) return;

    siginfo_t info = {.si_signo = sig, .si_code = SI_KERNEL};
    group_signal(tty_group, &info);

    if (!(termios.c_lflag & NOFLSH)) {
        line_len = echo_count = input_cnt = 0;
    }
}

static void do_single_unecho() {
    if (vt_state.x > 0) {
        vt_write_byte('\b');
        vt_write_byte(' ');
        vt_write_byte('\b');
    } else {
        unsigned char buf[16];
        size_t len = snprintk(buf, sizeof(buf), "\x1b[A\x1b[%dG", vt_state.x);
        ASSERT(len <= sizeof(buf));

        while (len--) {
            vt_write_byte(buf[len++]);
        }
    }
}

typedef enum {
    ECHO_IGNORE,
    ECHO_CONTROL,
    ECHO_NORMAL,
} echo_type_t;

static echo_type_t echo_type(unsigned char c) {
    if (c == 0 || c == '\t' || c == termios.c_cc[VSTART] || c == termios.c_cc[VSTOP]) return ECHO_IGNORE;
    if (c == '\n') return ECHO_NORMAL;
    if (c < 0x20) return ECHO_CONTROL;
    return ECHO_NORMAL;
}

static void do_echo(unsigned char c) {
    switch (echo_type(c)) {
    case ECHO_IGNORE: break;
    case ECHO_CONTROL:
        vt_write_byte('^');
        c += 0x40;
        // fall through
    case ECHO_NORMAL: vt_write_byte(c); break;
    }

    echo_count += 1;
}

static void do_unecho() {
again:
    if (!echo_count) return;
    ASSERT(input_cnt > line_len);

    unsigned char c = input_buf[input_cnt - 1];
    echo_count -= 1;

    switch (echo_type(c)) {
    case ECHO_IGNORE: goto again;
    case ECHO_CONTROL: do_single_unecho(); // fall through
    case ECHO_NORMAL: do_single_unecho(); break;
    }
}

static void console_process_byte(unsigned char c) {
    switch (c) {
    case 0: break; /* ensure c_cc values of 0 are interpreted as not present */
    case '\r':
        if (termios.c_iflag & ICRNL) c = '\n';
        if (termios.c_iflag & IGNCR) return;
        break;
    case '\n':
        if (termios.c_iflag & INLCR) c = '\r';
        break;
    default:
        if (termios.c_iflag & IXON) {
            if (c == termios.c_cc[VSTART]) {
                output_enabled = false;
                return;
            } else if (c == termios.c_cc[VSTOP]) {
                restart_output();
                return;
            }
        }

        if (termios.c_iflag & IXANY) {
            restart_output();
        }

        if (termios.c_lflag & ISIG) {
            if (c == termios.c_cc[VINTR]) {
                signal_after_char(SIGINT);
                return;
            } else if (c == termios.c_cc[VQUIT]) {
                signal_after_char(SIGQUIT);
                return;
            } else if (c == termios.c_cc[VSUSP]) {
                signal_after_char(SIGTSTP);
                return;
            }
        }

        if (termios.c_lflag & ICANON) {
            if (c == termios.c_cc[VERASE]) {
                if (termios.c_lflag & ECHOE) do_unecho();

                if (input_cnt > line_len) {
                    input_cnt -= 1;
                }

                return;
            } else if (c == termios.c_cc[VKILL]) {
                if (termios.c_lflag & ECHOK) {
                    while (echo_count) do_unecho();
                }

                line_len = input_cnt;
                return;
            }
        }

        break;
    }

    if (termios.c_iflag & ISTRIP) c &= 0x7f;
    if ((termios.c_iflag & IUCLC) && c >= 'A' && c <= 'Z') c |= 0x20;

    if (input_cnt >= input_cap) {
        size_t new_cap = input_cap ? input_cap * 2 : 8;
        void *new_buf = vmalloc(new_cap);
        memcpy(new_buf, input_buf, input_cap);
        vmfree(input_buf, input_cap);
        input_buf = new_buf;
        input_cap = new_cap;
    }

    input_buf[input_cnt++] = c;

    if (termios.c_lflag & ICANON) {
        if (c == '\n' && (termios.c_lflag & (ECHO | ECHONL)) == ECHONL) {
            do_echo(c);
        }

        if (is_eol(c)) {
            if (!line_len) line_len = input_cnt;
            echo_count = 0;
        }
    }

    if (termios.c_lflag & ECHO) do_echo(c);
}

void console_poll_events() {
    for (;;) {
        unsigned char c;
        if (!vt_read_byte(&c)) break;
        console_process_byte(c);
    }

    screen_flush();
    maybe_wake_readers();
}

void console_disconnect_from_session(bool on_exit) {
    console_disconnect_from_group();

    if (tty_session) {
        process_t *leader = get_session_leader(tty_session);

        if (leader) {
            leader->owns_tty = false;
        }

        if (tty_group) {
            siginfo_t info = {.si_signo = SIGHUP, .si_code = SI_KERNEL};
            group_signal(tty_group, &info);

            if (!on_exit) {
                info.si_signo = SIGCONT;
                group_signal(tty_group, &info);
            }
        }
    }

    tty_session = nullptr;
}

void console_disconnect_from_group() {
    if (tty_group) {
        tty_group->foreground = false;
    }

    tty_group = nullptr;
}
