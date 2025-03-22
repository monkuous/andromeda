#include "pmap.h"
#include "mem/layout.h"
#include "mem/pmem.h"
#include "util/panic.h"
#include <stdint.h>

#define PTE_PRESENT (1u << 0)
#define PTE_WRITABLE PMAP_WRITABLE
#define PTE_USER (1u << 2)
#define PTE_ACCESSED (1u << 5)
#define PTE_DIRTY (1u << 6)

#define TABLE_FLAGS (PTE_ACCESSED | PTE_USER | PTE_WRITABLE | PTE_PRESENT)

extern uint32_t kernel_page_dir[1024];

void pmap_alloc(uintptr_t virt, size_t size, uint32_t flags) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(virt >= KERN_VIRT_BASE);
    ASSERT(virt < virt + (size - 1));

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT(tail < PTBL_VIRT_BASE);

    flags |= PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;
        if (!kernel_page_dir[pdi]) kernel_page_dir[pdi] = pmem_alloc_simple() | TABLE_FLAGS;

        while (pti <= pti_end) {
            ASSERT(*table == 0);
            *table++ = pmem_alloc_simple() | flags;
            pti++;
        }

        pdi++;
        pti = 0;
    }
}
