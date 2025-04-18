#include "print.h"
#include "drv/console.h"
#include "drv/console/screen.h"
#include "fs/vfs.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/panic.h"
#include <stddef.h>

#define INT_BUF_SIZE 32

typedef void (*printk_sink_t)(const void *, size_t, void *);

static size_t printS(printk_sink_t sink, void *ctx, const void *buf, size_t len) {
    sink(buf, len, ctx);
    return len;
}

static size_t printc(printk_sink_t sink, void *ctx, unsigned char c) {
    return printS(sink, ctx, &c, sizeof(c));
}

static size_t prints(printk_sink_t sink, void *ctx, const char *str) {
    if (!str) str = "(null)";

    size_t len = 0;
    while (str[len]) len++;

    return printS(sink, ctx, str, len);
}

static size_t printu(printk_sink_t sink, void *ctx, unsigned value, unsigned min_digits) {
    unsigned char buffer[INT_BUF_SIZE];
    size_t index = sizeof(buffer);

    do {
        buffer[--index] = '0' + (value % 10);
        value /= 10;
    } while (index > 0 && value > 0);

    while (index > 0 && sizeof(buffer) - index < min_digits) {
        buffer[--index] = '0';
    }

    return printS(sink, ctx, &buffer[index], sizeof(buffer) - index);
}

static size_t printd(printk_sink_t sink, void *ctx, int value, unsigned min_digits) {
    size_t count = 0;

    if (value < 0) {
        count += printc(sink, ctx, '-');
        value = -value;
    }

    return count + printu(sink, ctx, value, min_digits);
}

static size_t printx(printk_sink_t sink, void *ctx, uint64_t value, unsigned min_digits) {
    unsigned char buffer[INT_BUF_SIZE];
    size_t index = sizeof(buffer);

    do {
        buffer[--index] = "0123456789abcdef"[value & 15];
        value >>= 4;
    } while (index > 0 && value > 0);

    while (index > 0 && sizeof(buffer) - index < min_digits) {
        buffer[--index] = '0';
    }

    return printS(sink, ctx, &buffer[index], sizeof(buffer) - index);
}

static size_t do_printk(printk_sink_t sink, void *ctx, const char *format, va_list args) {
    const char *last = format;
    size_t total = 0;

    for (char c = *format; c != 0; c = *++format) {
        if (c == '%') {
            if (last != format) {
                sink(last, format - last, ctx);
                total += format - last;
            }

            const char *start = format;
            unsigned min_digits = 0;

            for (;;) {
                char c = format[1];
                if (c < '0' || c > '9') break;
                min_digits = (min_digits * 10) + (c - '0');
                format++;
            }

            switch (*++format) {
            case '%': total += printc(sink, ctx, '%'); break;
            case 'c': total += printc(sink, ctx, (char)va_arg(args, int)); break;
            case 's': total += prints(sink, ctx, va_arg(args, const char *)); break;
            case 'S': {
                const void *buf = va_arg(args, const void *);
                size_t len = va_arg(args, size_t);
                total += printS(sink, ctx, buf, len);
                break;
            }
            case 'd': total += printd(sink, ctx, va_arg(args, int), min_digits); break;
            case 'u': total += printu(sink, ctx, va_arg(args, unsigned), min_digits); break;
            case 'x': total += printx(sink, ctx, va_arg(args, unsigned), min_digits); break;
            case 'X': total += printx(sink, ctx, va_arg(args, uint64_t), min_digits); break;
            case 'p':
                total += printS(sink, ctx, "0x", 2);
                total += printx(sink, ctx, (uintptr_t)va_arg(args, void *), 0);
                break;
            default:
                format = start;
                total += printc(sink, ctx, '%');
                break;
            }

            last = format + 1;
        }
    }

    if (last != format) {
        sink(last, format - last, ctx);
        total += format - last;
    }

    return total;
}

static bool print_to_console = true;

void print_set_console(bool console) {
    print_to_console = console;
}

static void term_sink(const void *buf, size_t size, void *) {
#if ANDROMEDA_QEMU_DEBUGCON
    const void *obuf = buf;
    size_t osize = size;
    asm volatile("rep outsb" : "+S" (obuf), "+c" (osize) :"d"(0xe9));
#endif

    if (print_to_console) console_write(buf, size);
}

void vprintk(const char *format, va_list args) {
    do_printk(term_sink, nullptr, format, args);
    screen_flush();
}

void printk(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
}

struct snprintk_ctx {
    void *buffer;
    size_t size;
};

static void snprintk_sink(const void *buf, size_t size, void *ptr) {
    struct snprintk_ctx *ctx = ptr;

    if (size > ctx->size) size = ctx->size;
    memcpy(ctx->buffer, buf, size);
    ctx->buffer += size;
    ctx->size -= size;
}

size_t vsnprintk(void *buffer, size_t size, const char *format, va_list args) {
    struct snprintk_ctx ctx = {buffer, size};
    return do_printk(snprintk_sink, &ctx, format, args);
}

size_t snprintk(void *buffer, size_t size, const char *format, ...) {
    va_list args;
    va_start(args, format);
    size_t length = vsnprintk(buffer, size, format, args);
    va_end(args);
    return length;
}

size_t vasprintk(char **output, const char *format, va_list args) {
    va_list args0;
    va_copy(args0, args);
    size_t length = vsnprintk(nullptr, 0, format, args0);
    va_end(args0);

    char *buffer = vmalloc(length);
    size_t final_len = vsnprintk(buffer, length, format, args);
    ASSERT(final_len == length);

    *output = buffer;
    return final_len;
}

size_t asprintk(char **output, const char *format, ...) {
    va_list args;
    va_start(args, format);
    size_t length = vasprintk(output, format, args);
    va_end(args);
    return length;
}

struct fprintk_ctx {
    file_t *file;
    int error;
};

static void vfprintk_sink(const void *data, size_t length, void *ptr) {
    struct fprintk_ctx *ctx = ptr;
    if (ctx->error) return;
    ctx->error = write_fully(ctx->file, data, length);
}

int vfprintk(file_t *file, const char *format, va_list args) {
    struct fprintk_ctx ctx = {file, 0};
    do_printk(vfprintk_sink, &ctx, format, args);
    return ctx.error;
}

int fprintk(file_t *file, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int error = vfprintk(file, format, args);
    va_end(args);
    return error;
}
