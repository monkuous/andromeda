#pragma once

#include "util/panic.h"
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

static inline uint16_t lin_to_seg(uint32_t phys, uint16_t *seg) {
    ASSERT(phys < 0x100000);

    *seg = phys >> 4;
    return phys & 15;
}

static inline uint32_t seg_to_lin(uint16_t seg, uint16_t off) {
    return ((uint32_t)seg << 4) + off;
}
