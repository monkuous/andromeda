#include "pmem.h"
#include "compiler.h"
#include "fs/pgcache.h"
#include "mem/bootmem.h"
#include "mem/layout.h"
#include "util/panic.h"
#include <stdint.h>

page_t *page_array;
pmem_stats_t pmem_stats;

static page_t *free_pages;

uint32_t pmem_alloc_simple() {
    if (unlikely(!page_array)) return bootmem_alloc();

    return page_to_phys(pmem_alloc(false));
}

page_t *pmem_alloc(bool cache) {
    if (unlikely(!free_pages)) {
        page_t *page = pgcache_evict();
        if (unlikely(!page)) panic("pmem: out of memory");

        if (!cache) {
            pmem_stats.cache -= 1;
            pmem_stats.alloc += 1;
        }

        return page;
    }

    page_t *page = free_pages;
    size_t idx = --page->free.count;
    if (likely(!idx)) free_pages = page->free.next;

    if (cache) pmem_stats.cache += 1;
    else pmem_stats.alloc += 1;

    return page + idx;
}

void pmem_free(page_t *page, bool cache) {
    page->free.count = 1;
    page->free.next = free_pages;
    free_pages = page;

    if (cache) pmem_stats.cache -= 1;
    else pmem_stats.alloc -= 1;
}

static void do_add(uint32_t head, uint32_t tail) {
    extern const void _end;

    uint32_t kern_tail = (KERN_TO_PHYS((uintptr_t)&_end) - 1) | PAGE_MASK;

    if (tail >= KERN_PHYS_BASE && head <= kern_tail) {
        uint32_t overlap_head = head > KERN_PHYS_BASE ? head : KERN_PHYS_BASE;
        uint32_t overlap_tail = tail < kern_tail ? tail : kern_tail;

        pmem_stats.alloc += ((overlap_tail - overlap_head) >> PAGE_SHIFT) + 1;

        if (head < overlap_head) do_add(head, overlap_head - 1);
        if (tail <= overlap_tail) return;
        head = overlap_tail + 1;
    }

    size_t count = ((tail - head) >> PAGE_SHIFT) + 1;

    page_t *page = phys_to_page(head);
    page->free.count = count;
    page->free.next = free_pages;
    free_pages = page;
}

void pmem_add_region(uint32_t head, uint32_t tail, uint32_t alloc_tail) {
    ASSERT(head < tail);
    ASSERT(!(head & PAGE_MASK));
    ASSERT((tail & PAGE_MASK) == PAGE_MASK);
    ASSERT((alloc_tail & PAGE_MASK) == PAGE_MASK);

    size_t pages = ((tail - head) >> PAGE_SHIFT) + 1;
    pmem_stats.total += pages;

    if (head == 0) {
        pmem_stats.alloc += 1;

        if (tail <= PAGE_MASK) return;

        head = PAGE_SIZE;
        pages -= 1;
    }

    if (alloc_tail < tail) {
        if (alloc_tail < head) {
            pmem_stats.alloc += pages;
            return;
        }

        pmem_stats.alloc += pages - (((alloc_tail - head) >> PAGE_SHIFT) + 1);
        tail = alloc_tail;
    }

    do_add(head, tail);
}
