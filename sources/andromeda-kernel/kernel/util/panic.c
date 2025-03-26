#include "panic.h"
#include "init/bios.h"
#include "util/print.h"
#include <stdarg.h>

[[noreturn]] void panic(const char *format, ...) {
    // clear keyboard buffer
    while (true) {
        regs_t regs = {.eax = 0x100};
        intcall(0x16, &regs);
        if (regs.eflags & 0x40) break;

        regs = (regs_t){};
        intcall(0x16, &regs);
    }

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
