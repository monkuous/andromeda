#include "pmap.h"
#include "mem/layout.h"
#include "mem/pmem.h"
#include "util/panic.h"
#include "string.h"
#include <stdint.h>

#define PTE_PRESENT (1u << 0)
#define PTE_WRITABLE PMAP_WRITABLE
#define PTE_USER (1u << 2)
#define PTE_ACCESSED (1u << 5)
#define PTE_DIRTY (1u << 6)
#define PTE_ANON (1u << 9)
#define PTE_ADDR 0xfffff000

#define TABLE_FLAGS (PTE_ACCESSED | PTE_USER | PTE_WRITABLE | PTE_PRESENT)

#define CUR_PAGE_DIR ((uint32_t *)(PTBL_VIRT_BASE | (PTBL_VIRT_BASE >> 10)))

extern uint32_t kernel_page_dir[1024];

static uint32_t *temp_map_pte;
alignas(PAGE_SIZE) static char temp_map_page[PAGE_SIZE];

static inline void invlpg(uintptr_t addr) {
    asm("invlpg (%0)" ::"r"(addr) : "memory");
}

void init_pmap() {
    temp_map_pte = (uint32_t *)(PTBL_VIRT_BASE | ((uintptr_t)temp_map_page >> 10));
}

static void ensure_pt_present(uint32_t *pd, uint32_t pdi) {
    if (!pd[pdi]) {
        pd[pdi] = pmem_alloc_simple() | TABLE_FLAGS;
        memset((uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)), 0, 0x1000);
    }
}

void pmap_map(uintptr_t virt, uint32_t phys, size_t size, uint32_t flags) {
    ASSERT(!((virt | phys | size) & PAGE_MASK));
    ASSERT(virt >= KERN_VIRT_BASE);

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
        ensure_pt_present(kernel_page_dir, pdi);

        while (pti <= pti_end) {
            ASSERT(*table == 0);
            *table++ = phys | flags;
            pti++;
            phys += 0x1000;
        }

        pdi++;
        pti = 0;
    }
}

void pmap_alloc(uintptr_t virt, size_t size, uint32_t flags) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(virt >= KERN_VIRT_BASE);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT(tail < PTBL_VIRT_BASE);

    flags |= PTE_ANON | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;
        ensure_pt_present(kernel_page_dir, pdi);

        while (pti <= pti_end) {
            ASSERT(*table == 0);
            *table++ = pmem_alloc_simple() | flags;
            pti++;
        }

        pdi++;
        pti = 0;
    }
}

void pmap_unmap(uintptr_t virt, size_t size) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(virt >= KERN_VIRT_BASE);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT((virt < KERN_VIRT_BASE) == (tail < KERN_VIRT_BASE));
    ASSERT(tail < PTBL_VIRT_BASE);

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *directory = virt < KERN_VIRT_BASE ? CUR_PAGE_DIR : kernel_page_dir;
    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;

        if (directory[pdi]) {
            while (pti <= pti_end) {
                uint32_t pte = *table;

                if (pte) {
                    *table = 0;
                    invlpg((pdi << 22) | (pti << 12));

                    if (pte & PTE_ANON) {
                        pmem_free(phys_to_page(pte & PTE_ADDR), false);
                    }
                }

                table++;
                pti++;
            }
        } else {
            table += pti_end - pti;
        }

        pdi++;
        pti = 0;
    }
}

void *pmap_tmpmap(uint32_t phys) {
    ASSERT(!(phys & PAGE_MASK));

    uint32_t pte = phys | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    if (pte != *temp_map_pte) {
        *temp_map_pte = pte;
        invlpg((uintptr_t)temp_map_page);
    }

    return temp_map_page;
}
