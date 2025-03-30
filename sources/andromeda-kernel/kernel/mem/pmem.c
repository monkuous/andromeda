#include "pmem.h"
#include "compiler.h"
#include "fs/pgcache.h"
#include "mem/bootmem.h"
#include "mem/layout.h"
#include "string.h"
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
    page += idx;

    page->is_free = false;
    page->is_cache = false;

    if (cache) pmem_stats.cache += 1;
    else pmem_stats.alloc += 1;

    return page;
}

void pmem_free(page_t *page, bool cache) {
    page->is_free = true;
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
    memset(page, 0xff, count * sizeof(*page)); // set is_free to 1 for all pages in this region
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

struct alloc_slow_ctx {
    union {
        uint32_t offset;
        page_t *page;
    };
    uint32_t max_tail;
};

static bool alloc_slow_func(uint64_t head, uint64_t tail, memory_type_t type, void *ptr) {
    if (type != MEM_USABLE) return true;
    if (tail < PAGE_MASK) return true;
    tail = (tail - PAGE_MASK) | PAGE_MASK;

    struct alloc_slow_ctx *ctx = ptr;

    if (tail < ctx->offset) return true;
    if (tail > ctx->max_tail) tail = ctx->max_tail;

    uint32_t alloc_head = tail - ctx->offset;
    uint32_t count = (ctx->offset >> PAGE_SHIFT) + 1;

    while (head <= alloc_head) {
        page_t *base = phys_to_page(alloc_head);
        uint32_t i;
        bool has_cache = false;

        for (i = count; i > 0; i--) {
            page_t *page = &base[i - 1];

            if (!page->is_free) {
                if (page->is_cache) {
                    has_cache = true;
                    continue;
                }

                uint32_t new_alloc_tail = page_to_phys(page) - 1;
                if (new_alloc_tail < ctx->offset) return true;
                alloc_head = new_alloc_tail - ctx->offset;
                break;
            }
        }

        if (i) continue;

        if (has_cache) {
            for (i = 0; i < count; i++) {
                page_t *page = &base[i];

                if (page->is_cache) {
                    pgcache_evict_specific(page);
                }
            }
        }

        memset(base, 0, count); // set is_free and is_cache to 0 for all pages
        pmem_stats.alloc += count;

        ctx->page = base;
        return false;
    }

    return true;
}

page_t *pmem_alloc_slow(size_t count, uint32_t max_addr) {
    if (!count) return page_array;

    if (max_addr < PAGE_MASK) return nullptr;
    max_addr = (max_addr - PAGE_MASK) | PAGE_MASK;

    uint32_t offset = ((count - 1) << PAGE_SHIFT) | PAGE_MASK;
    if (max_addr < offset) return nullptr;

    struct alloc_slow_ctx ctx = {
            .offset = offset,
            .max_tail = max_addr,
    };

    return !bootmem_iter(alloc_slow_func, &ctx, true) ? ctx.page : nullptr;
}

void pmem_free_multiple(page_t *pages, size_t count) {
    if (!count) return;

    memset(pages, 0xff, count * sizeof(*pages)); // set is_free to 1 for all pages
    pages->free.count = count;
    pages->free.next = free_pages;
    free_pages = pages;
    pmem_stats.alloc -= count;
}
