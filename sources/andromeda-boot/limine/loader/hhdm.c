#include "hhdm.h"
#include "libboot.h"
#include "main.h"
#include "memory.h"
#include "paging.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void init_hhdm() {
    boot_info.responses.hhdm.offset = min_higher_half_address;
}

void create_hhdm() {
    size_t map_size;
    const libboot_mem_region_t *map = libboot_mem_get_map(&map_size);

    struct {
        uint64_t head;
        uint64_t tail;
        bool framebuffer;
    } *ranges = nullptr;
    size_t nranges = 0;

    for (size_t i = 0; i < map_size; i++) {
        if (map[i].type != LIBBOOT_MEMORY_USABLE && map[i].type != LIMINE_MEMORY_LOADER &&
            map[i].type != LIMINE_MEMORY_KERNEL && map[i].type != LIMINE_MEMORY_FRAMEBUFFER) {
            printf("hhdm: skipping 0x%llx-0x%llx (%d)\n", map[i].head, map[i].tail, map[i].type);
            continue;
        }

        uint64_t head = map[i].head;
        uint64_t tail = map[i].tail;

        if (map[i].type == LIMINE_MEMMAP_USABLE) {
            if (tail < 0xfff) continue;
            head = (head + 0xfff) & ~0xfff;
            tail = (tail - 0xfff) | 0xfff;
            if (head > tail) continue;
        } else {
            head &= ~0xfff;
            tail |= 0xfff;
        }

        bool cur_fb = map[i].type == LIMINE_MEMORY_FRAMEBUFFER;

        if (nranges != 0 && ranges[nranges - 1].tail + 1 == head && ranges[nranges - 1].framebuffer == cur_fb) {
            ranges[nranges - 1].tail = tail;
        } else {
            size_t idx = nranges++;
            ranges = realloc(ranges, nranges * sizeof(*ranges));
            ranges[idx].head = head;
            ranges[idx].tail = tail;
            ranges[idx].framebuffer = cur_fb;
        }
    }

    for (size_t i = 0; i < nranges; i++) {
        printf("hhdm: mapping 0x%llx-0x%llx\n", ranges[i].head, ranges[i].tail);
        paging_map(
                boot_info.responses.hhdm.offset + ranges[i].head,
                ranges[i].head,
                ranges[i].tail - ranges[i].head + 1,
                PAGE_WRITABLE | PAGE_EXECUTABLE | (ranges[i].framebuffer ? PAGE_FRAMEBUFFER : 0)
        );
    }
}
