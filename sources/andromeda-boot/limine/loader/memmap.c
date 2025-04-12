#include "memmap.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "memory.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static void iter_memmap(void (*cb)(struct limine_memmap_entry *entry, void *ctx), void *ctx) {
    size_t count;
    const libboot_mem_region_t *mmap = libboot_mem_get_map(&count);

    struct limine_memmap_entry entry;
    bool have_one = false;

    for (size_t i = 0; i < count; i++) {
        const libboot_mem_region_t *cur = &mmap[i];

        uint64_t head = cur->head;
        uint64_t tail = cur->tail;
        uint64_t type;

        switch (cur->type) {
        case LIBBOOT_MEMORY_USABLE: type = LIMINE_MEMMAP_USABLE; break;
        case LIBBOOT_MEMORY_ACPI_RECLAIMABLE: type = LIMINE_MEMMAP_ACPI_RECLAIMABLE; break;
        case LIBBOOT_MEMORY_ACPI_NVS: type = LIMINE_MEMMAP_ACPI_NVS; break;
        case LIMINE_MEMORY_LOADER: type = LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE; break;
        case LIMINE_MEMORY_KERNEL: type = LIMINE_MEMMAP_EXECUTABLE_AND_MODULES; break;
        case LIMINE_MEMORY_FRAMEBUFFER: type = LIMINE_MEMMAP_FRAMEBUFFER; break;
        default: type = LIMINE_MEMMAP_RESERVED; break;
        }

        if (type == LIMINE_MEMMAP_USABLE) {
            if (tail < 0xfff) continue;

            head = (head + 0xfff) & ~0xfff;
            tail = (tail - 0xfff) | 0xfff;

            if (head > tail) continue;

            if (!have_one || entry.type != LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE || entry.base + entry.length != head) {
                /* All usable regions are immediately preceded by a bootloader-reclaimable region.
                 * This ensures that the prekernel will not run out of space in the memory map
                 * when it needs to allocate something. */
                entry.base = head;
                entry.length = 0;
                entry.type = LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE;
                cb(&entry, ctx);
            }
        }

        entry.base = head;
        entry.length = tail - head + 1;
        entry.type = type;
        have_one = true;

        cb(&entry, ctx);
    }
}

static void count_entries_cb(struct limine_memmap_entry *, void *) {
    boot_info.responses.memmap.entry_count += 1;
}

struct fill_ctx {
    struct limine_memmap_entry *entries;
    size_t index;
};

static void fill_entries_cb(struct limine_memmap_entry *entry, void *ptr) {
    struct fill_ctx *ctx = ptr;
    ctx->entries[ctx->index++] = *entry;
}

void init_memmap() {
    // allocate space for two more entries than present in the memory map,
    // because an allocation might add two more entries
    boot_info.responses.memmap.entry_count = 2;
    iter_memmap(count_entries_cb, nullptr);

    size_t count = boot_info.responses.memmap.entry_count;
    size_t ptrs_size = count * sizeof(uint64_t);
    size_t data_size = count * sizeof(struct limine_memmap_entry);
    size_t area_size = ptrs_size + data_size;
    paddr_t area_phys = UINT32_MAX; // the prekernel needs to be able to access these
    void *area_virt = alloc_pages(&area_phys, area_size, 8, LIMINE_MEMORY_LOADER);

    uint64_t *pointers = area_virt;

    for (size_t i = 0; i < count; i++) {
        pointers[i] = boot_info.responses.hhdm.offset + area_phys + ptrs_size + i * sizeof(struct limine_memmap_entry);
    }

    struct fill_ctx ctx = {area_virt + ptrs_size, .index = 0};
    iter_memmap(fill_entries_cb, &ctx);
    memset(&ctx.entries[ctx.index], 0, (count - ctx.index) * sizeof(*ctx.entries));

    boot_info.responses.memmap.entries = boot_info.responses.hhdm.offset + area_phys;
    boot_info.responses.memmap.entry_count = count;
}
