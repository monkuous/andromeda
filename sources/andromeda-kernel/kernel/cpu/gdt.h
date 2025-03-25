#pragma once

#define GDT_SEL_KCODE 0x08
#define GDT_SEL_KDATA 0x10
#define GDT_SEL_UCODE 0x18
#define GDT_SEL_UDATA 0x20
#define GDT_SEL_BCODE 0x28
#define GDT_SEL_BDATA 0x30
#define GDT_SEL_KTASK 0x38
#define GDT_SEL_DF_TASK 0x40

#ifndef __ASSEMBLER__

#include <stdint.h>

typedef struct {
    uint16_t prev;
    uint32_t esp0;
    uint16_t ss0;
    uint32_t esp1;
    uint16_t ss1;
    uint32_t esp2;
    uint16_t ss2;
    uint32_t cr3;
    uint32_t eip;
    uint32_t eflags;
    uint32_t eax;
    uint32_t ecx;
    uint32_t edx;
    uint32_t ebx;
    uint32_t esp;
    uint32_t ebp;
    uint32_t esi;
    uint32_t edi;
    uint16_t es;
    alignas(4) uint16_t cs;
    alignas(4) uint16_t ss;
    alignas(4) uint16_t ds;
    alignas(4) uint16_t fs;
    alignas(4) uint16_t gs;
    alignas(4) uint16_t ldt;
    alignas(4) bool trap;
    uint16_t io_map_base;
} tss_t;

extern tss_t kernel_tss, dfault_tss;

void init_gdt();

#endif /* defined(__ASSEMBLER__) */
