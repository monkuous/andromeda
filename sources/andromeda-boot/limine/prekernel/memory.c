#include "memory.h"
#include "bootinfo.h"
#include "limine.h"
#include "start.h"
#include "string.h"
#include <stddef.h>
#include <stdint.h>

uint32_t allocate_pages(size_t count) {
    if (!count) return 0x1000;

    size_t i = boot_info->responses.memmap.entry_count;
    uint64_t *entries = (void *)(uintptr_t)(boot_info->responses.memmap.entries - boot_info->responses.hhdm.offset);

    size_t size = count << 12;

    while (i > 0) {
        struct limine_memmap_entry *entry = (void *)(uintptr_t)(entries[i - 1] - boot_info->responses.hhdm.offset);

        if (entry->type != LIMINE_MEMMAP_USABLE || entry->base > UINT32_MAX ||
            (UINT32_MAX - entry->base) < (size - 1) || entry->length < size) {
            i -= 1;
            continue;
        }

        uint32_t addr = entry->base;
        if (!addr) {
            // allocate_pages must not return page 0
            entry[-1].length += 0x1000;
            entry->base += 0x1000;
            entry->length -= 0x1000;
            continue;
        }

        // The loader ensures that all usable entries are immediately preceded
        // by an adjacent bootloader reclaimable entry by inserting zero-length
        // entries. Expand the entry for this one, and shrink the usable entry.
        // We don't have to remove it if this was the last page in this region,
        // since memory_cleanup() removes all zero-length entries.
        entry[-1].length += size;
        entry->base += size;
        entry->length -= size;

        return addr;
    }

    die();
}

void *allocate(size_t size) {
    static uint32_t next = 0;
    size = (size + 7) & ~7;

    if (!(next & 0xfff) || (0x1000 - (next & 0xfff)) < size) {
        next = allocate_pages(1);
    }

    uint32_t addr = next;
    next += size;
    return (void *)addr;
}

alignas(0x1000) static unsigned char tmpmap_area[0x1000];

void memory_cleanup() {
    size_t i = 0;
    uint64_t *entries = (void *)(uintptr_t)(boot_info->responses.memmap.entries - boot_info->responses.hhdm.offset);

    while (i < boot_info->responses.memmap.entry_count) {
        struct limine_memmap_entry *entry = (void *)(uintptr_t)(entries[i] - boot_info->responses.hhdm.offset);

        if (entry->length) {
            i += 1;
            continue;
        }

        uint64_t new_count = --boot_info->responses.memmap.entry_count;
        memmove(&entries[i], &entries[i + 1], (new_count - i) * sizeof(*entries));
    }

    // restore the proper direct mapping
    tmpmap((uintptr_t)tmpmap_area, true);
}

void *tmpmap(uint64_t address, bool cache) {
    uintptr_t virt = (uintptr_t)tmpmap_area;

    uint64_t *table;
    asm("mov %%cr3, %0" : "=r"(table)); // this doesn't need volatile, since cr3 can't change
    int level = boot_info->pt_levels - 1;

    while (level > 0) {
        table = (uint64_t *)(uintptr_t)(table[((uint64_t)virt >> (level * 9 + 12)) & 511] & 0xffffffffff000);
        level -= 1;
    }

    uint64_t flags = 0x63;     // dirty, accessed, writable, present
    if (!cache) flags |= 0x18; // PAT = 3, which points to UC (also works without PAT)
    uint64_t entry = (address & ~0xfff) | flags;
    uint64_t *pte = &table[(virt >> 12) & 511];

    if (*pte != entry) {
        *pte = entry;
        asm("invlpg (%0)" ::"r"(virt)
            : "memory"); // memory clobber makes compiler think we could've written to tmpmap_area
    }

    return (void *)(uintptr_t)(virt | (address & 0xfff));
}

void copy_from_phys(void *dest, uint64_t address, size_t size, bool cache) {
    while (size) {
        size_t pgoff = address & 0xfff;
        size_t pgrem = 0x1000 - pgoff;
        size_t curcp = size < pgrem ? size : pgrem;

        memcpy(dest, tmpmap(address, cache), curcp);

        dest += curcp;
        address += curcp;
        size -= curcp;
    }
}
