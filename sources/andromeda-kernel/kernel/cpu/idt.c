#include "idt.h"
#include "asm/cr.h"
#include "cpu/gdt.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

typedef struct [[gnu::packed, gnu::aligned(2)]] {
    uint16_t limit;
    void *base;
} idt_desc_t;

static uint64_t idt[0x21]; /* 0x00-0x1f: reserved for architectural use, 0x20: syscall */
extern uintptr_t idt_thunks[0x21];

idt_desc_t kernel_idt_desc = {sizeof(idt) - 1, idt};

static uint64_t create_task_entry(uint16_t selector) {
    return 0x850000000000ull | ((uint32_t)selector << 16);
}

static uint64_t create_irq_entry(uintptr_t thunk, uint8_t dpl) {
    return 0x8e0000000000ull | ((uint32_t)GDT_SEL_KCODE << 16) | (thunk & 0xffff) | ((thunk & 0xffff0000ull) << 32) |
           ((uint64_t)dpl << 45);
}

[[noreturn]] static void handle_fatal_exception(idt_frame_t *frame, bool stack_info_valid) {
    uint32_t esp;
    uint16_t ss;

    if (stack_info_valid) {
        esp = frame->esp;
        ss = frame->ss;
    } else {
        esp = (uintptr_t)&frame[1];
        asm("mov %%ss, %0" : "=rm"(ss));
    }

    uint32_t cr0 = read_cr0();
    uint32_t cr2 = read_cr2();
    uint32_t cr3 = read_cr3();

    panic("fatal exception 0x%2x at 0x%8x (error code 0x%x)\n"
          "eax=0x%8x ebx=0x%8x ecx=0x%8x edx=0x%8x cs=0x%4x ds=0x%4x\n"
          "esi=0x%8x edi=0x%8x ebp=0x%8x esp=0x%8x es=0x%4x fs=0x%4x\n"
          "efl=0x%8x cr0=0x%8x cr2=0x%8x cr3=0x%8x gs=0x%4x ss=0x%4x",
          frame->vector,
          frame->eip,
          frame->error,
          frame->eax,
          frame->ebx,
          frame->ecx,
          frame->edx,
          frame->cs,
          frame->ds,
          frame->esi,
          frame->edi,
          frame->ebp,
          esp,
          frame->es,
          frame->fs,
          frame->eflags,
          cr0,
          cr2,
          cr3,
          frame->gs,
          ss);
}

[[noreturn]] static void handle_task_exception(uint32_t vector, tss_t *tss) {
    tss_t *prev;

    switch (tss->prev) {
    case GDT_SEL_KTASK: prev = &kernel_tss; break;
    case GDT_SEL_DF_TASK: prev = &dfault_tss; break;
    default: prev = nullptr; break;
    }

    idt_frame_t frame = {
            .eax = prev->eax,
            .ebx = prev->ebx,
            .ecx = prev->ecx,
            .edx = prev->edx,
            .esi = prev->esi,
            .edi = prev->edi,
            .ebp = prev->ebp,
            .ds = prev->ds,
            .es = prev->es,
            .fs = prev->fs,
            .gs = prev->gs,
            .vector = vector,
            .eip = prev->eip,
            .cs = prev->cs,
            .eflags = prev->eflags,
            .esp = prev->esp,
            .ss = prev->ss,
    };

    handle_fatal_exception(&frame, true);
}

static void setup_task_exception(tss_t *tss, uint32_t vector, size_t stack_offset) {
    tss->cr3 = read_cr3();
    tss->eip = (uintptr_t)handle_task_exception;
    tss->eax = vector;
    tss->edx = (uintptr_t)tss;
    tss->esp = tss->esp0 - stack_offset;
    tss->es = GDT_SEL_KDATA;
    tss->cs = GDT_SEL_KCODE;
    tss->ss = GDT_SEL_KDATA;
    tss->ds = GDT_SEL_KDATA;
    tss->fs = GDT_SEL_KDATA;
    tss->gs = GDT_SEL_KDATA;
}

void init_idt() {
    setup_task_exception(&dfault_tss, 8, 0);

    for (size_t i = 0; i < sizeof(idt_thunks) / sizeof(*idt_thunks); i++) {
        uintptr_t thunk = idt_thunks[i];
        if (!thunk) continue;

        idt[i] = create_irq_entry(thunk, 0);
    }

    idt[8] = create_task_entry(GDT_SEL_DF_TASK);
    idt[0x20] = create_irq_entry(idt_thunks[0x20], 3);
}

idt_frame_t *idt_dispatch(idt_frame_t *frame) {
    handle_fatal_exception(frame, frame->cs & 3);
    return frame;
}
