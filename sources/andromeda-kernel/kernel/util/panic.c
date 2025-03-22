#include "panic.h"
#include "init/bios.h"
#include "util/print.h"
#include <stdarg.h>

[[noreturn]] void panic(const char *format, ...) {
    va_list args;
    va_start(args, format);
    printk("\nkernel panic: ");
    vprintk(format, args);
    printk("\n");
    va_end(args);

    while (true) {
        rm_halt();
    }
}
