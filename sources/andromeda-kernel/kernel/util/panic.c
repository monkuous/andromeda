#include "panic.h"
#include "init/bios.h"
#include "util/print.h"
#include <stdarg.h>

[[noreturn]] void panic(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printk("\nkernel panic: ");
    vprintk(format, args);
    printk("\npress any key to restart\n");
    va_end(args);

    regs_t regs = {};
    intcall(0x16, &regs);
    intcall(0x19, &regs);
    __builtin_unreachable();
}
