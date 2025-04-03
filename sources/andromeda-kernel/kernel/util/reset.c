#include "reset.h"
#include <stdint.h>

#define I8042_DATA 0x60
#define I8042_CMDS 0x64

#define I8042_COMMAND_PULSE_OUTPUT 0xf0

#define I8042_STATUS_INPUT_FULL 2

static inline void outb(uint16_t port, uint8_t value) {
    asm("outb %0, %1" ::"a"(value), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t value;
    asm("inb %1, %0" : "=a" (value) : "Nd" (port));
    return value;
}

static void i8042_wait() {
    for (;;) {
        if (!(inb(I8042_CMDS) & I8042_STATUS_INPUT_FULL)) break;
    }
}

void reset_system() {
    i8042_wait();
    outb(I8042_CMDS, I8042_COMMAND_PULSE_OUTPUT | 0xe); // pulse bit 0 of output

    // wait for the 8042 to run the command
    uint16_t i = 0xffff;
    while (--i) outb(0x80, 0);

    // we're still alive? just triple fault
    asm("pushl $0; pushl $0; lidt (%esp); ljmp $0xffff, $0");
    __builtin_unreachable();
}
