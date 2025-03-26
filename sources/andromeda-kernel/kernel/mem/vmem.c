#include "vmem.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "string.h"
#include "util/hash.h"
#include "util/panic.h"
#include <stdint.h>

// number of slots in the allocated ranges hash table
// there is no fixed cap on the number of items in the table, but increasing this improves performance
#define ALLOC_TABLE_SIZE 256
#define ALLOC_TABLE_MASK (ALLOC_TABLE_SIZE - 1)

struct vmem_range {
    struct vmem_range *prev;
    struct vmem_range *next;
    struct vmem_range *kind_prev;
    struct vmem_range *kind_next;
    uintptr_t start;
    size_t size;
    int order;
    bool free;
};

#define MIN_ORDER PAGE_SHIFT
#define MAX_ORDER 32

static struct vmem_range *ranges;
static struct vmem_range *free_ranges[MAX_ORDER - MIN_ORDER];
static uint32_t free_bitmap;
static struct vmem_range *allocations[ALLOC_TABLE_SIZE];

static struct vmem_range *unalloc_ranges;
static size_t num_unalloc_ranges;

static void alloc_more_ranges() {
    static bool allocating_ranges;
    if (allocating_ranges) return;
    allocating_ranges = true;

    uintptr_t addr = vmem_alloc(PAGE_SIZE);
    pmap_alloc(addr, PAGE_SIZE, PMAP_WRITABLE);

    for (size_t i = 0; i < PAGE_SIZE / sizeof(struct vmem_range); i++) {
        struct vmem_range *range = (struct vmem_range *)addr;
        addr += sizeof(struct vmem_range);

        range->next = unalloc_ranges;
        unalloc_ranges = range;
        num_unalloc_ranges += 1;
    }

    allocating_ranges = false;
}

static struct vmem_range *range_alloc() {
    static struct vmem_range static_ranges[8];
    static size_t num_static_ranges = sizeof(static_ranges) / sizeof(*static_ranges);

    // a single vmem_alloc call allocates, at most, 1 range. if we only have 1 left, use it to allocate more.
    if (num_static_ranges + num_unalloc_ranges <= 1) {
        alloc_more_ranges();
    }

    struct vmem_range *range = unalloc_ranges;

    if (range) {
        unalloc_ranges = range->next;
        num_unalloc_ranges -= 1;
    } else if (num_static_ranges) {
        range = &static_ranges[--num_static_ranges];
    } else {
        panic("range_alloc failed");
    }

    return range;
}

static void range_free(struct vmem_range *range) {
    range->next = unalloc_ranges;
    unalloc_ranges = range;
    num_unalloc_ranges += 1;
}

// size >= 1
static int get_lower_p2(size_t size) {
    return (31 - MIN_ORDER) - __builtin_clzl(size);
}

// size >= 2
static int get_higher_p2(size_t size) {
    return (32 - MIN_ORDER) - __builtin_clzl(size - 1);
}

static void global_remove(struct vmem_range *range) {
    if (range->prev) range->prev->next = range->next;
    else ranges = range->next;
    if (range->next) range->next->prev = range->prev;
}

static void global_insert(struct vmem_range *range) {
    if (range->prev) range->prev->next = range;
    else ranges = range;
    if (range->next) range->next->prev = range;
}

static void kind_remove(struct vmem_range *range, struct vmem_range **list) {
    if (range->kind_prev) range->kind_prev->kind_next = range->kind_next;
    else *list = range->kind_next;
    if (range->kind_next) range->kind_next->kind_prev = range->kind_prev;
}

static void free_remove(struct vmem_range *range, int order) {
    kind_remove(range, &free_ranges[order]);
    if (!free_ranges[order]) free_bitmap &= ~(1ul << order);
}

static void kind_insert(struct vmem_range *range, struct vmem_range **list) {
    range->kind_prev = nullptr;
    range->kind_next = *list;
    if (range->kind_next) range->kind_next->kind_prev = range;
    *list = range;
}

static void free_insert(struct vmem_range *range, int order) {
    kind_insert(range, &free_ranges[order]);
    free_bitmap |= 1ul << order;
}

static void update_order(struct vmem_range *range) {
    int new_order = get_lower_p2(range->size);

    if (new_order != range->order) {
        free_remove(range, range->order);
        free_insert(range, new_order);
        range->order = new_order;
    }
}

static bool try_merge(struct vmem_range *prev, struct vmem_range *next, uintptr_t start, size_t size) {
    bool prev_merge = prev != nullptr && prev->free && prev->start + prev->size == start;
    bool next_merge = next != nullptr && next->free && start + size == next->start;

    if (prev_merge) {
        prev->size += size;

        if (next_merge) {
            prev->size += next->size;
            prev->next = next->next;
            if (prev->next) prev->next->prev = prev;
            global_remove(next);
            free_remove(next, next->order);
            range_free(next);
        }

        update_order(prev);
        return true;
    } else if (next_merge) {
        next->start -= size;
        next->size += size;
        update_order(next);

        return true;
    } else {
        return false;
    }
}

static void merge_or_insert(struct vmem_range *prev, struct vmem_range *next, uintptr_t start, size_t size) {
    if (!try_merge(prev, next, start, size)) {
        struct vmem_range *range = range_alloc();
        memset(range, 0, sizeof(*range));
        range->start = start;
        range->size = size;
        range->prev = prev;
        range->next = next;
        range->order = get_lower_p2(size);
        range->free = true;

        global_insert(range);
        free_insert(range, range->order);
    }
}

void vmem_add_range(uintptr_t head, uintptr_t tail) {
    ASSERT(head < tail);
    ASSERT(!(head & PAGE_MASK));
    ASSERT((tail & PAGE_MASK) == PAGE_MASK);

    size_t size = (tail - head) + 1;

    struct vmem_range *prev = nullptr;
    struct vmem_range *next = ranges;

    while (next != nullptr && next->start < head) {
        prev = next;
        next = next->next;
    }

    ASSERT(prev == nullptr || (prev->start + prev->size) <= head);
    ASSERT(next == nullptr || head + size <= next->start);

    merge_or_insert(prev, next, head, size);
}

uintptr_t vmem_alloc(size_t size) {
    ASSERT((size & PAGE_MASK) == 0);
    int wanted_order = get_higher_p2(size);

    int order = __builtin_ffsl(free_bitmap >> wanted_order);
    struct vmem_range *range;

    if (unlikely(order == 0)) {
        if (wanted_order != 0 && size != (1ul << wanted_order)) {
            // The previous free list might have a range that's big enough
            order = wanted_order - 1;
            range = free_ranges[order];
            while (range != nullptr && range->size < size) range = range->next;

            if (unlikely(range == nullptr)) panic("vmem: out of memory");
        } else {
            panic("vmem: out of memory");
        }
    } else {
        order += wanted_order - 1;
        range = free_ranges[order];
    }

    struct vmem_range *alloc;

    if (range->size != size) {
        alloc = range_alloc();
        memset(alloc, 0, sizeof(*alloc));
        alloc->start = range->start;
        alloc->size = size;
        alloc->prev = range->prev;
        alloc->next = range;
        alloc->free = false;
        global_insert(alloc);

        range->start += size;
        range->size -= size;
        update_order(range);
    } else {
        alloc = range;
        range->free = false;
        free_remove(range, order);
    }

    kind_insert(alloc, &allocations[make_hash_int32(alloc->start) & ALLOC_TABLE_MASK]);
    return alloc->start;
}

static struct vmem_range *get_range_from_alloc(uint64_t hash, uintptr_t start, [[maybe_unused]] size_t size) {
    struct vmem_range *range = allocations[hash & ALLOC_TABLE_MASK];

    for (;;) {
        ASSERT(range != nullptr);
        if (range->start == start) break;
        range = range->kind_next;
    }

    ASSERT(range != nullptr);
    ASSERT(range->size == size);
    ASSERT(!range->free);
    return range;
}

void vmem_free(uintptr_t addr, size_t size) {
    ASSERT((addr & PAGE_MASK) == 0);
    ASSERT((size & PAGE_MASK) == 0);

    uint64_t hash = make_hash_int32(addr);
    struct vmem_range *range = get_range_from_alloc(hash, addr, size);
    kind_remove(range, &allocations[hash & ALLOC_TABLE_MASK]);

    struct vmem_range *prev = range->prev;
    struct vmem_range *next = range->next;

    if (!try_merge(prev, next, addr, size)) {
        range->free = true;
        range->order = get_lower_p2(range->size);
        free_insert(range, range->order);
    } else {
        global_remove(range);
        range_free(range);
    }
}
