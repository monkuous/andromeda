#pragma once

#include "util/list.h"
#include <stddef.h>
#include <stdint.h>

#define PAGE_SHIFT 12
#define PAGE_SIZE (1ul << PAGE_SHIFT)
#define PAGE_MASK (PAGE_SIZE - 1)

typedef struct [[gnu::aligned(32)]] page {
    bool is_free : 1;
    bool is_cache : 1;
    union {
        struct {
            struct page *next;
            size_t count;
        } free;
        struct {
            size_t references;
        } anon;
        struct {
            list_node_t lru_node;
            struct pgcache *cache;
            uint64_t index;
        } cache;
    };
} page_t;

typedef struct {
    uint32_t total;
    uint32_t alloc;
    uint32_t cache;
} pmem_stats_t;

extern page_t *page_array;
extern pmem_stats_t pmem_stats;

uint32_t pmem_alloc_simple();

// might evict 1 page, but no more than that, and the data of the evicted page is untouched
page_t *pmem_alloc(bool cache);

void pmem_free(page_t *page, bool cache);

int pmem_alloc_slow(page_t **out, size_t count, size_t align, uint32_t max_addr);
void pmem_free_multiple(page_t *pages, size_t count);

void pmem_add_region(uint32_t head, uint32_t tail, uint32_t alloc_tail);

static inline uint32_t page_to_phys(page_t *page) {
    return (uint32_t)(page - page_array) << 12;
}

static inline page_t *phys_to_page(uint32_t phys) {
    return page_array + (phys >> 12);
}
