#include "print.h"
#include "init/bios.h"
#include <stddef.h>

#define INT_BUF_SIZE 32

static void printc(unsigned char c) {
#if ANDROMEDA_QEMU_DEBUGCON
    asm("outb %0, $0xe9" ::"a"(c));
#endif

    regs_t regs = {.eax = 0xe00};

    if (c == '\n') {
        regs.eax |= '\r';
        intcall(0x10, &regs);
    }

    regs.eax = (regs.eax & ~0xff) | c;
    intcall(0x10, &regs);
}

static void prints(const char *str) {
    if (!str) str = "(null)";

    for (char c = *str; c != 0; c = *++str) {
        printc(c);
    }
}

static void printS(const unsigned char *buf, size_t count) {
    while (count--) {
        printc(*buf++);
    }
}

static void printu(unsigned value, unsigned min_digits) {
    unsigned char buffer[INT_BUF_SIZE];
    size_t index = sizeof(buffer);

    do {
        buffer[--index] = '0' + (value % 10);
        value /= 10;
    } while (index > 0 && value > 0);

    while (index > 0 && sizeof(buffer) - index < min_digits) {
        buffer[--index] = '0';
    }

    printS(&buffer[index], sizeof(buffer) - index);
}

static void printd(int value, unsigned min_digits) {
    if (value < 0) {
        printc('-');
        value = -value;
    }

    printu(value, min_digits);
}

static void printx(uint64_t value, unsigned min_digits) {
    unsigned char buffer[INT_BUF_SIZE];
    size_t index = sizeof(buffer);

    do {
        buffer[--index] = "0123456789abcdef"[value & 15];
        value >>= 4;
    } while (index > 0 && value > 0);

    while (index > 0 && sizeof(buffer) - index < min_digits) {
        buffer[--index] = '0';
    }

    printS(&buffer[index], sizeof(buffer) - index);
}

void vprintk(const char *format, va_list args) {
    for (char c = *format; c != 0; c = *++format) {
        if (c == '%') {
            const char *start = format;
            unsigned min_digits = 0;

            for (;;) {
                char c = format[1];
                if (c < '0' || c > '9') break;
                min_digits = (min_digits * 10) + (c - '0');
                format++;
            }

            switch (*++format) {
            case '%': printc('%'); break;
            case 'c': printc((char)va_arg(args, int)); break;
            case 's': prints(va_arg(args, const char *)); break;
            case 'S': {
                const void *buf = va_arg(args, const void *);
                size_t len = va_arg(args, size_t);
                printS(buf, len);
                break;
            }
            case 'd': printd(va_arg(args, int), min_digits); break;
            case 'u': printu(va_arg(args, unsigned), min_digits); break;
            case 'x': printx(va_arg(args, unsigned), min_digits); break;
            case 'X': printx(va_arg(args, uint64_t), min_digits); break;
            default:
                format = start;
                printc('%');
                break;
            }
        } else {
            printc(c);
        }
    }
}

void printk(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintk(format, args);
    va_end(args);
}
