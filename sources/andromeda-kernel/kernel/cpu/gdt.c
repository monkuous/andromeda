#include "gdt.h"
#include <stddef.h>
#include <stdint.h>

extern struct {
    uint64_t reserved;
    uint64_t kern_code;
    uint64_t kern_data;
    uint64_t user_code;
    uint64_t user_data;
    uint64_t bios_code;
    uint64_t bios_data;
    uint64_t kern_task;
    uint64_t df_task;
    uint64_t nmi_task;
} kernel_gdt;

tss_t kernel_tss, dfault_tss, nmi_tss;

static uint64_t create_tss_seg(tss_t *tss) {
    uintptr_t addr = (uintptr_t)tss;

    return (sizeof(*tss) - 1) | ((addr & 0xffffff) << 16) | ((addr & 0xff000000ull) << 32) | 0x890000000000;
}

static void setup_tss(uint64_t *segment, tss_t *tss) {
    extern const void _start;

    tss->esp0 = (uintptr_t)&_start;
    tss->ss0 = GDT_SEL_KDATA;
    tss->io_map_base = sizeof(*tss) - 1;

    *segment = create_tss_seg(tss);
}

void init_gdt() {
    setup_tss(&kernel_gdt.kern_task, &kernel_tss);
    setup_tss(&kernel_gdt.df_task, &dfault_tss);
    setup_tss(&kernel_gdt.nmi_task, &nmi_tss);

    asm("ltr %w0" ::"r"(GDT_SEL_KTASK));
}
