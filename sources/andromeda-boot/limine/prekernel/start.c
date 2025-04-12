#include "start.h"
#include "acpi.h"
#include "asm.h"
#include "bootinfo.h"
#include "irq.h"
#include "memory.h"
#include "smp.h"
#include <stdint.h>

[[gnu::used]] uint64_t hhdm_offset;
boot_info_t *boot_info;

[[gnu::used]] uint64_t run_prekernel(boot_info_t *info) {
    boot_info = info;
    hhdm_offset = info->responses.hhdm.offset;

    if (info->flags & BOOT_INFO_SETUP_PAT) {
        /* 0-5: WB, WT, UC-, UC, WP, WC */
        wrmsr(0x277, 0x010500070406);
    }

    init_acpi();
    init_irq();
    if (info->mp_response_field_ptr) init_smp();

    memory_cleanup(); // This must be the LAST thing done before returning.
    return info->entry_point;
}

void die() {
    asm("1: hlt; jmp 1b");
    __builtin_unreachable();
}
