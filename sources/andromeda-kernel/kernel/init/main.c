#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "init/bios.h"
#include "mem/bootmem.h"
#include "mem/memdetect.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

static void init_video() {
    // ensure video mode is 3 (80x25 color text)
    regs_t regs = {.eax = 0xf00};
    intcall(0x10, &regs);

    if ((regs.eax & 0xff) != 3) {
        regs = (regs_t){.eax = 3};
        intcall(0x10, &regs);
    }
}

[[noreturn, gnu::used]] void kernel_main([[maybe_unused]] uint64_t boot_lba, [[maybe_unused]] uint8_t boot_drive) {
    init_gdt();
    init_idt();
    init_video();
    printk("\nStarting Andromeda...\n");
    detect_memory();
    bootmem_handover();

    panic("TODO");
}
