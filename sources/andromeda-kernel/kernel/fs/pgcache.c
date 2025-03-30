#include "pgcache.h"
#include "compiler.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/container.h"
#include "util/list.h"
#include "util/panic.h"
#include <errno.h>
#include <stdint.h>

#define LEVEL_SHIFT 6
#define LEVEL_COUNT (1ul << LEVEL_SHIFT)
#define LEVEL_MASK (LEVEL_COUNT - 1)

#define TABLE_SIZE (LEVEL_COUNT * sizeof(void *))

static list_t pgcache_lru;

static bool is_evictable(pgcache_t *cache) {
    return cache->ops != nullptr;
}

static void lru_add(page_t *page) {
    list_insert_tail(&pgcache_lru, &page->cache.lru_node);
}

static void lru_del(page_t *page) {
    list_remove(&pgcache_lru, &page->cache.lru_node);
}

static void lru_refresh(page_t *page) {
    list_remove(&pgcache_lru, &page->cache.lru_node);
    list_insert_tail(&pgcache_lru, &page->cache.lru_node);
}

static void **get_ptr(pgcache_t *cache, uint64_t index, bool alloc) {
    if (cache->levels == 0) return &cache->data;

    void **ptr = &cache->data;
    unsigned shift = LEVEL_SHIFT * (cache->levels - 1);

    ASSERT(!((index >> shift) & ~(uint64_t)LEVEL_MASK));

    for (size_t i = 0; i < cache->levels; i++) {
        void **table = *ptr;

        if (!table) {
            if (!alloc) return nullptr;
            table = *ptr = vmalloc(TABLE_SIZE);
            memset(table, 0, TABLE_SIZE);
        }

        size_t tidx = (index >> shift) & LEVEL_MASK;
        ptr = &table[tidx];
        shift -= LEVEL_SHIFT;
    }

    return ptr;
}

static void *cache_del(pgcache_t *cache, uint64_t index) {
    ASSERT(index < cache->pages);

    void **ptr = get_ptr(cache, index, false);
    if (!ptr) return nullptr;

    void *value = *ptr;
    *ptr = nullptr;
    return value;
}

int pgcache_get_page(pgcache_t *cache, page_t **out, uint64_t index, bool create) {
    if (index >= cache->pages) return ENXIO;

    bool evictable = is_evictable(cache);
    if (evictable) create = true;

    void **ptr = get_ptr(cache, index, create);
    if (!ptr) {
        ASSERT(!create);
        *out = nullptr;
        return 0;
    }

    page_t *page = *ptr;

    if (page) {
        if (evictable) lru_refresh(page);
    } else if (create) {
        page = pmem_alloc(evictable);
        page->cache.cache = cache;
        page->cache.index = index;

        if (evictable) {
            int error = cache->ops->read_page(cache, page, index);
            if (unlikely(error)) {
                pmem_free(page, evictable);
                return error;
            }

            page->is_cache = true;
            lru_add(page);
        } else {
            memset(pmap_tmpmap(page_to_phys(page)), 0, PAGE_SIZE);
        }

        *ptr = page;
    }

    *out = page;
    return 0;
}

static size_t levels_for_size(uint64_t size) {
    if (size < 2) return 0;

    unsigned bits = 64 - __builtin_clzll(size - 1);
    return (bits + (LEVEL_SHIFT - 1)) / LEVEL_SHIFT;
}

static void handle_eviction(pgcache_t *, page_t *) {
    // TODO: Unmap
}

static void free_entry(pgcache_t *cache, void *ptr, size_t level, bool evictable) {
    if (!ptr) return;

    if (level == 0) {
        page_t *page = ptr;
        if (evictable) lru_del(page);
        handle_eviction(cache, page);
        pmem_free(page, evictable);
    } else {
        void **table = ptr;

        for (size_t i = 0; i < LEVEL_COUNT; i++) {
            free_entry(cache, table[i], level - 1, evictable);
        }

        vmfree(table, TABLE_SIZE);
    }
}

void pgcache_resize(pgcache_t *cache, uint64_t size) {
    size = (size + PAGE_MASK) >> PAGE_SHIFT;

    size_t new_levels = levels_for_size(size);

    if (size < cache->pages) {
        bool evictable = is_evictable(cache);

        while (new_levels < cache->levels) {
            void **table = cache->data;

            for (size_t i = 1; i < LEVEL_COUNT; i++) {
                free_entry(cache, table[i], cache->levels - 1, evictable);
            }

            cache->data = table[0];
            cache->levels -= 1;
            vmfree(table, TABLE_SIZE);
        }

        ASSERT(cache->levels == new_levels);

        if (cache->levels != 0) {
            void **table = cache->data;
            size_t offset = size & LEVEL_MASK;

            for (size_t i = offset; i < LEVEL_COUNT; i++) {
                free_entry(cache, table[i], cache->levels - 1, evictable);
            }
        } else if (size == 0) {
            free_entry(cache, cache->data, 0, evictable);
            cache->data = nullptr;
        }
    } else {
        while (cache->levels < new_levels) {
            void **table = vmalloc(TABLE_SIZE);
            table[0] = cache->data;
            memset(&table[1], 0, TABLE_SIZE - sizeof(*table));
            cache->data = table;
            cache->levels += 1;
        }

        ASSERT(cache->levels == new_levels);
    }

    cache->pages = size;
}

page_t *pgcache_evict() {
    page_t *page = container(page_t, cache.lru_node, list_remove_head(&pgcache_lru));

    if (page) {
        pgcache_evict_specific(page);
    }

    return page;
}

void pgcache_evict_specific(page_t *page) {
    [[maybe_unused]] page_t *deleted = cache_del(page->cache.cache, page->cache.index);
    ASSERT(deleted == page);

    handle_eviction(page->cache.cache, page);
}

int pgcache_read(pgcache_t *cache, void *buffer, size_t size, uint64_t offset) {
    ASSERT(size);
    ASSERT(((offset + (size - 1)) >> PAGE_SHIFT) < cache->pages);

    uint64_t index = offset >> PAGE_SHIFT;
    size_t pgoff = offset & PAGE_MASK;
    size_t pgrem = PAGE_SIZE - pgoff;

    while (size) {
        size_t cur = pgrem < size ? pgrem : size;

        page_t *page;
        int error = pgcache_get_page(cache, &page, index, false);
        if (unlikely(error)) return error;

        if (page) {
            // TODO: Use user_memcpy
            memcpy(buffer, pmap_tmpmap(page_to_phys(page)) + pgoff, cur);
        } else {
            // TODO: Use user_memset
            memset(buffer, 0, cur);
        }

        buffer += cur;
        size -= cur;
        index += 1;
        pgoff = 0;
        pgrem = PAGE_SIZE;
    }

    return 0;
}

int pgcache_write(pgcache_t *cache, const void *buffer, size_t size, uint64_t offset) {
    ASSERT(size);
    ASSERT(((offset + (size - 1)) >> PAGE_SHIFT) < cache->pages);
    ASSERT(!is_evictable(cache));

    uint64_t index = offset >> PAGE_SHIFT;
    size_t pgoff = offset & PAGE_MASK;
    size_t pgrem = PAGE_SIZE - pgoff;

    while (size) {
        size_t cur = pgrem < size ? pgrem : size;

        page_t *page;
        int error = pgcache_get_page(cache, &page, index, true);
        if (unlikely(error)) return error;

        // TODO: Use user_memcpy
        memcpy(pmap_tmpmap(page_to_phys(page)) + pgoff, buffer, cur);

        buffer += cur;
        size -= cur;
        index += 1;
        pgoff = 0;
        pgrem = PAGE_SIZE;
    }

    return 0;
}
