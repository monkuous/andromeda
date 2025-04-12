#include "irq.h"
#include "acpi.h"
#include "asm.h"
#include "memory.h"
#include <stddef.h>

static void disable_pic() {
    outb(0x21, 0xff);
    outb(0xa1, 0xff);
}

void init_irq() {
    uint64_t madt_addr;
    size_t madt_len = get_table(TABLE_MADT, &madt_addr);
    if (!madt_len) {
        // if there's no madt, assume presence of legacy pic
        disable_pic();
        return;
    }

    madt_t header;
    copy_from_phys(&header, madt_addr, sizeof(header), true);
    if (header.flags & MADT_PCAT_COMPAT) disable_pic();

    uint64_t madt_end = madt_addr + madt_len;
    madt_addr += sizeof(header);

    while (madt_addr < madt_end) {
        madt_entry_t entry;
        copy_from_phys(&entry, madt_addr, 2, true);

        if (entry.type == MADT_IOAPIC) {
            copy_from_phys(&entry.ioapic, madt_addr + 2, sizeof(entry.ioapic), true);

            void *ptr = tmpmap(entry.ioapic.address, false);

            mmio_write32(ptr, 1);
            uint32_t irqs = (mmio_read32(ptr + 0x10) >> 16) & 0xff;

            for (uint32_t i = 0; i < irqs; i++) {
                mmio_write32(ptr, 0x10 + i * 2);
                uint32_t value = mmio_read32(ptr + 0x10);

                // only mask irqs with default or lowest priority delivery modes
                if ((value & 0x300) <= 0x100) {
                    mmio_write32(ptr + 0x10, value | 0x10000);
                }
            }
        }

        madt_addr += entry.length;
    }
}
