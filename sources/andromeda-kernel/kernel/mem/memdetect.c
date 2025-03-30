#include "memdetect.h"
#include "init/bios.h"
#include "mem/bootmem.h"
#include "mem/layout.h"
#include <stdint.h>

#define E820_MAGIC 0x534d4150

typedef struct [[gnu::packed]] {
    uint64_t base;
    uint64_t size;
    uint32_t type;
} e820_buf_t;

static bool detect_e820() {
    uint32_t key = 0;
    e820_buf_t buf;
    bool success = false;

    do {
        regs_t regs = {
                .eax = 0xe820,
                .ebx = key,
                .ecx = sizeof(buf),
                .edx = E820_MAGIC,
                .edi = KERN_TO_PHYS((uintptr_t)&buf),
        };
        intcall(0x15, &regs);
        if ((regs.eflags & 1) != 0 || regs.eax != E820_MAGIC) break;
        success = true;
        key = regs.ebx;

        memory_type_t type;

        switch (buf.type) {
        case 1: type = MEM_USABLE; break;
        case 3: type = MEM_ACPI_RECLAIM; break;
        case 4: type = MEM_ACPI_NVS; break;
        default: type = MEM_RESERVED; break;
        }

        bootmem_add(buf.base, buf.size, type);
    } while (key != 0);

    return success;
}

static void detect_low() {
    regs_t regs = {};
    intcall(0x12, &regs);
    bootmem_add(0, (uint32_t)(regs.eax & 0xffff) << 10, MEM_USABLE);
}

static bool detect_e801() {
    regs_t regs = {.eax = 0xe801};
    intcall(0x15, &regs);
    if (regs.eflags & 1) return false;

    uint16_t low = regs.ecx;
    uint16_t high = regs.edx;

    if (!low) {
        low = regs.eax;
        high = regs.ebx;
    }

    bootmem_add(0x100000, (uint32_t)low << 10, MEM_USABLE);
    bootmem_add(0x1000000, (uint32_t)high << 16, MEM_USABLE);

    return true;
}

static bool detect_88() {
    regs_t regs = {.eax = 0x88};
    intcall(0x15, &regs);
    if (regs.eflags & 1) return false;

    bootmem_add(0x100000, (uint32_t)(regs.eax & 0xffff) << 10, MEM_USABLE);
    return true;
}

void detect_memory() {
    if (detect_e820()) return;
    detect_low();
    if (detect_e801()) return;
    if (detect_88()) return;
}
