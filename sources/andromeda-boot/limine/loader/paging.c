#include "paging.h"
#include "bootinfo.h"
#include "cpufeat.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "memory.h"
#include "requests.h"
#include "utils.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PTE_PRESENT 1
#define PTE_WRITABLE 2
#define PTE_ACCESSED 0x20
#define PTE_DIRTY 0x40
#define PTE_DIRECT 0x80
#define PTE_FRAMEBUFFER 0x88 /* PAT = 5 */
#define PTE_ADDR 0xffffffffff000
#define PTE_NX 0x8000000000000000

typedef struct pte {
    uint64_t *real;
    struct pte *shadow;
} pte_t;

uint32_t top_page_table_phys;
uint64_t min_higher_half_address;

static pte_t top_page_table;
static int pt_levels;

static paddr_t alloc_page_table(pte_t *entry) {
    paddr_t paddr = UINT32_MAX; // the prekernel needs to be able to access the page tables
    entry->real = alloc_pages(&paddr, 0x1000, 0x1000, LIMINE_MEMORY_LOADER);
    entry->shadow = malloc(sizeof(*entry->shadow) * 512);
    memset(entry->real, 0, 0x1000);
    // don't need to clear entry->shadow, entry->real is authoritative for whether the corresponding shadow entry exists
    return paddr;
}

static bool is_mode_supported(uint64_t mode) {
    switch (mode) {
    case LIMINE_PAGING_MODE_X86_64_4LVL: return true;
    case LIMINE_PAGING_MODE_X86_64_5LVL: return cpufeat.la57;
    default: return false;
    }
}

static uint64_t pick_mode(uint64_t min, uint64_t max) {
    for (uint64_t i = max + 1; i > min; i--) {
        uint64_t mode = i - 1;

        if (is_mode_supported(mode)) return mode;
    }

    fprintf(stderr, "%s: no paging modes supported by both cpu and executable\n", progname);
    exit(1);
}

void init_paging() {
    struct limine_paging_mode_request *request = get_request(REQUEST_PAGING_MODE);
    uint64_t mode;

    if (request) {
        mode = request->mode;

        if (!is_mode_supported(mode)) {
            mode = pick_mode(
                    request->revision >= 1 ? request->min_mode : LIMINE_PAGING_MODE_MIN,
                    request->revision >= 1 ? request->max_mode : request->mode
            );
        }
    } else {
        mode = LIMINE_PAGING_MODE_DEFAULT;
    }

    boot_info.responses.paging_mode.mode = mode;

    switch (mode) {
    case LIMINE_PAGING_MODE_X86_64_4LVL: pt_levels = 4; break;
    case LIMINE_PAGING_MODE_X86_64_5LVL:
        pt_levels = 5;
        kernel_cr4_value |= 1u << 12; /* LA57 */
        break;
    default: unreachable();
    }

    top_page_table_phys = alloc_page_table(&top_page_table);
    min_higher_half_address = ((uint64_t)-1) << (pt_levels * 9 + 12 - 1);
    boot_info.pt_levels = pt_levels;
}

static bool can_map_direct(int level) {
    return level <= 1 || (level == 2 && cpufeat.direct_1gb);
}

static uint64_t get_pte(uint64_t phys, int flags, int level) {
    phys |= PTE_PRESENT | PTE_ACCESSED | PTE_DIRTY;

    if (flags & PAGE_WRITABLE) phys |= PTE_WRITABLE;
    if (!(flags & PAGE_EXECUTABLE)) phys |= PTE_NX;
    if (flags & PAGE_FRAMEBUFFER) phys |= PTE_FRAMEBUFFER;

    if (level != 0) {
        phys |= (phys & PTE_DIRECT) << 5; // move PAT bit from index 7 to 12
        phys |= PTE_DIRECT;
    }

    return phys;
}

static void do_map(pte_t *table, int level, uint64_t virt, uint64_t phys, uint64_t size, int flags) {
    unsigned child_bits = level * 9 + 12;
    uint64_t child_size = 1ull << child_bits;
    uint64_t child_mask = child_size - 1;

    uint64_t idx = (virt >> child_bits) & 511;
    uint64_t rem = child_size - (virt & child_mask);

    while (size) {
        uint64_t cur = rem < size ? rem : size;

        if (can_map_direct(level) && cur == child_size && !(phys & child_mask)) {
            assert(!table->real[idx]);
            table->real[idx] = get_pte(phys, flags, level);
        } else {
            assert(level > 0);
            pte_t *child = &table->shadow[idx];

            if (!table->real[idx]) {
                table->real[idx] = alloc_page_table(child) | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;
            } else {
                assert(!(table->real[idx] & PTE_DIRECT));
            }

            do_map(child, level - 1, virt, phys, cur, flags);
        }

        virt += cur;
        phys += cur;
        size -= cur;

        idx += 1;
        rem = child_size;
    }
}

void paging_map(uint64_t virt, uint64_t phys, uint64_t size, int flags) {
    assert(!((virt | phys | size) & 0xfff));
    assert(virt >= min_higher_half_address);
    assert(size > 0);
    assert(virt + (size - 1) >= virt);

    if (!cpufeat.nx) flags |= PAGE_EXECUTABLE;
    if (!cpufeat.pat) flags &= ~PAGE_FRAMEBUFFER;

    do_map(&top_page_table, pt_levels - 1, virt, phys, size, flags);
}

void paging_finalize() {
    memcpy(top_page_table.real, &top_page_table.real[256], 0x800);
}

uint64_t paging_resolve(uint64_t virt) {
    printf("paging_resolve(0x%llx)\n", virt);
    pte_t *table = &top_page_table;

    for (int i = pt_levels - 1; i > 0; i--) {
        unsigned bits = i * 9 + 12;
        size_t idx = (virt >> bits) & 511;
        uint64_t entry = table->real[idx];
        assert(entry);

        if (entry & PTE_DIRECT) {
            return (entry & (PTE_ADDR & ~0x1000)) | (virt & ((1ull << bits) - 1));
        }

        table = &table->shadow[idx];
    }

    return (table->real[(virt >> 12) & 511] & PTE_ADDR) | (virt & 0xfff);
}
