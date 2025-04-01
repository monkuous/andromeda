#pragma once

#include <stdint.h>

typedef struct {
    uint32_t edi;
    uint32_t esi;
    uint32_t ebp;
    uint32_t reserved;
    uint32_t ebx;
    uint32_t edx;
    uint32_t ecx;
    uint32_t eax;
    uint16_t ds;
    uint16_t es;
    uint16_t fs;
    uint16_t gs;
    uint32_t vector;
    uint32_t error;
    uint32_t eip;
    uint16_t cs;
    uint32_t eflags;
    uint32_t esp;
    uint16_t ss;
} idt_frame_t;

[[noreturn]] void handle_fatal_exception(idt_frame_t *frame);
[[noreturn]] void idt_return(idt_frame_t *frame); // frame must be allocated on the stack

void init_idt();
