#include "bootmem.h"
#include "mem/layout.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "string.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

#define MMAP_CAPACITY 128

typedef struct {
    uint64_t head;
    uint64_t tail;
    memory_type_t type;
} mem_region_t;

static mem_region_t memory_map[MMAP_CAPACITY];
static size_t mmap_count;
static bool mmap_frozen;

static void do_insert(size_t index, uint64_t head, uint64_t tail, memory_type_t type) {
    ASSERT(index <= mmap_count);

    if (mmap_count == MMAP_CAPACITY) panic("too many memory regions");

    memmove(&memory_map[index + 1], &memory_map[index], (mmap_count - index) * sizeof(*memory_map));
    memory_map[index].head = head;
    memory_map[index].tail = tail;
    memory_map[index].type = type;
    mmap_count += 1;
}

static void remove(size_t index) {
    ASSERT(index < mmap_count);

    memmove(&memory_map[index], &memory_map[index + 1], (mmap_count - index - 1) * sizeof(*memory_map));
    mmap_count -= 1;
}

// returns the index of the entry that the region is now in
static size_t insert(size_t index, uint64_t head, uint64_t tail, memory_type_t type) {
    ASSERT(index <= mmap_count);
    ASSERT(index == 0 || memory_map[index - 1].tail < head);
    ASSERT(index == mmap_count || tail < memory_map[index].head);

    bool merge_prev = index > 0 && memory_map[index - 1].type == type && memory_map[index - 1].tail + 1 == head;
    bool merge_next = index < mmap_count && memory_map[index].type == type && tail + 1 == memory_map[index].head;

    if (merge_prev) {
        if (merge_next) {
            memory_map[index - 1].tail = memory_map[index].tail;
            remove(index);
        } else {
            memory_map[index - 1].tail = tail;
        }

        return index - 1;
    } else if (merge_next) {
        memory_map[index].head = head;
        return index;
    } else {
        do_insert(index, head, tail, type);
        return index;
    }
}

static void do_add(uint64_t head, uint64_t tail, memory_type_t type) {
    size_t idx = mmap_count;

    while (idx > 0 && memory_map[idx - 1].tail >= head) {
        idx -= 1;
    }

    // idx is the index of the lowest memory region that might overlap the new one (region.tail >= head)

    while (head <= tail) {
        if (idx >= mmap_count || memory_map[idx].head > tail) {
            insert(idx, head, tail, type);
            break;
        }

        mem_region_t *region = &memory_map[idx];

        if (region->tail < head) {
            idx += 1;
            continue;
        }

        // region->head <= tail && region->tail >= head
        // idx overlaps with new region

        uint64_t rhead = region->head;

        if (head < rhead) {
            idx = insert(idx, head, rhead - 1, type);
            head = rhead;
            continue;
        }

        uint64_t rtail = region->tail;
        memory_type_t rtype = region->type;

        if (rtype >= type) {
            // keep the existing region
            if (rtail >= tail) break;

            head = rtail + 1;
            idx += 1;
            continue;
        }

        // keep new region

        bool have_pre = rhead < head;
        bool have_post = tail < rtail;

        if (!have_pre && !have_post) {
            remove(idx);
            continue;
        }

        if (!have_pre) {
            region->head = tail + 1;
            continue;
        }

        region->tail = head - 1;
        if (!have_post) continue;

        idx = insert(idx + 1, tail + 1, rtail, rtype);
    }
}

void bootmem_add(uint64_t base, uint64_t size, memory_type_t type) {
    if (mmap_frozen) panic("tried to add to mmap after freeze");
    if (!size) return;

    uint64_t tail = base + (size - 1);
    if (base > tail) tail = UINT64_MAX;

    do_add(base, tail, type);
}

static size_t max_alloc_idx = SIZE_MAX;
static uint32_t max_alloc_tail = UINT32_MAX;

extern const void _end;

uint32_t bootmem_alloc() {
    if (!mmap_frozen) panic("bootmem_alloc called before freezing mmap");

    for (size_t i = max_alloc_idx < mmap_count ? max_alloc_idx : mmap_count; i > 0; i--) {
        mem_region_t *region = &memory_map[i - 1];
        if (region->type != MEM_USABLE) continue;
        if (region->tail < PAGE_MASK) continue;

        uint64_t alloc_tail = (region->tail - PAGE_MASK) | PAGE_MASK;

        if (alloc_tail > max_alloc_tail) alloc_tail = max_alloc_tail;
        if (alloc_tail >= KERN_PHYS_BASE && alloc_tail - PAGE_MASK < KERN_TO_PHYS((uintptr_t)&_end)) {
            alloc_tail = (KERN_PHYS_BASE - PAGE_SIZE) | PAGE_MASK;
        }

        uint32_t alloc_head = alloc_tail - PAGE_MASK;
        if (alloc_head <= (0x600 | PAGE_MASK)) continue;

        max_alloc_idx = i;
        max_alloc_tail = alloc_head - 1;
        return alloc_head;
    }

    panic("out of memory");
}

static void iter_usable_regions_aligned(void (*func)(uint64_t, uint64_t, void *), void *ctx) {
    for (size_t i = 0; i < mmap_count; i++) {
        mem_region_t *region = &memory_map[i];
        if (region->type != MEM_USABLE) continue;

        uint64_t aligned_head = (region->head + PAGE_MASK) & ~PAGE_MASK;
        if (region->head > aligned_head) continue;

        uint64_t aligned_tail = (region->tail - PAGE_MASK) | PAGE_MASK;
        if (region->tail < aligned_tail) continue;

        if (aligned_head > aligned_tail) continue;

        func(aligned_head, aligned_tail, ctx);
    }
}

struct find_bounds_ctx {
    uint64_t cur_head;
    uint64_t cur_tail;
};

static void find_bounds(uint64_t head, uint64_t tail, void *ptr) {
    struct find_bounds_ctx *ctx = ptr;

    if (head < ctx->cur_head) ctx->cur_head = head;
    if (tail > ctx->cur_tail) ctx->cur_tail = tail;
}

static void add_regions(uint64_t head, uint64_t tail, void *) {
    if (tail > UINT32_MAX) tail = UINT32_MAX;
    if (head > tail) return;

    pmem_add_region(head, tail, max_alloc_tail);
}

void bootmem_handover() {
    mmap_frozen = true;

    struct find_bounds_ctx bounds = {UINT64_MAX, 0};
    iter_usable_regions_aligned(find_bounds, &bounds);

    if (bounds.cur_tail > UINT32_MAX) bounds.cur_tail = UINT32_MAX;
    if (bounds.cur_head > bounds.cur_tail) panic("no usable memory");

    size_t page_base = bounds.cur_head >> PAGE_SHIFT;
    size_t num_pages = ((bounds.cur_tail - bounds.cur_head) >> PAGE_SHIFT) + 1;
    size_t parr_size = num_pages * sizeof(page_t);

    uintptr_t parr_vhead = ((uintptr_t)&_end + (alignof(page_t) - 1)) & ~(alignof(page_t) - 1);
    uintptr_t parr_vtail = parr_vhead + (parr_size - 1);
    uintptr_t parr_vhead_aligned = (parr_vhead + PAGE_MASK) & ~PAGE_MASK;
    uintptr_t parr_vtail_aligned = parr_vtail | PAGE_MASK;

    if (parr_vhead_aligned < parr_vtail_aligned) {
        pmap_alloc(parr_vhead_aligned, parr_vtail_aligned - parr_vhead_aligned + 1, PMAP_WRITABLE);
    }

    max_alloc_idx = 0; // disable bootmem_alloc
    page_array = (page_t *)parr_vhead - page_base;

    iter_usable_regions_aligned(add_regions, nullptr);
}
