#pragma once

#include <stdint.h>

typedef struct {
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t esp;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
    uint16_t ds;
    uint16_t es;
    uint16_t fs;
    uint16_t gs;
    uint32_t eflags;
} regs_t;

void intcall(uint8_t vector, regs_t *regs);

// runs the hlt instruction in real mode, giving the bios a chance to process interrupts
static inline void rm_halt() {
    regs_t regs = {.eflags = 0x200};
    intcall(0xff, &regs);
}
