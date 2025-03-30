#pragma once

#include "mem/pmem.h"
#include <stddef.h>
#include <stdint.h>

typedef struct pgcache pgcache_t;

typedef struct {
    int (*read_page)(pgcache_t *self, page_t *page, uint64_t idx);
} pgcache_ops_t;

struct pgcache {
    const pgcache_ops_t *ops;
    uint64_t pages;

    void *data;
    size_t levels;
};

// NOTE: If `create` is false, the function may indicate success when returning
// null. This indicates that the given page has no data.
//
// WARNING: The returned page is only valid until the next memory allocation,
// because any memory allocation is allowed to evict a page from the page cache.
int pgcache_get_page(pgcache_t *cache, page_t **out, uint64_t index, bool create);
int pgcache_read(pgcache_t *cache, void *buffer, size_t size, uint64_t offset);
int pgcache_write(pgcache_t *cache, const void *buffer, size_t size, uint64_t offset);

void pgcache_resize(pgcache_t *cache, uint64_t size);

page_t *pgcache_evict();
