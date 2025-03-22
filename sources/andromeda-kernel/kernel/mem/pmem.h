#pragma once

#include <stddef.h>
#include <stdint.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ul << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)

typedef union page {
    struct {
        union page *next;
        size_t count;
    } free;
} page_t;

typedef struct {
    uint32_t total;
    uint32_t alloc;
    uint32_t cache;
} pmem_stats_t;

extern page_t *page_array;
extern pmem_stats_t pmem_stats;

uint32_t pmem_alloc_simple();
page_t *pmem_alloc(bool cache);
void pmem_free(page_t *page, bool cache);

void pmem_add_region(uint32_t head, uint32_t tail, uint32_t alloc_tail);

static inline uint32_t page_to_phys(page_t *page) {
    return (uint32_t)(page - page_array) << 12;
}

static inline page_t *phys_to_page(uint32_t phys) {
    return page_array + (phys >> 12);
}
