#pragma once

#include "libboot.h"
#include "main.h"
#include "memory.h"
#include "utils.h"
#include <stddef.h>
#include <stdint.h>
#include <string.h>

static inline uint64_t create_pointer_array(void *data, size_t entry_size, size_t count) {
    if (!count) return 0;

    size_t data_size = entry_size * count;
    size_t ptrs_size = count * sizeof(uint64_t);
    size_t total_size = data_size + ptrs_size;

    paddr_t phys = UINT64_MAX;
    void *ptr = alloc_pages(&phys, total_size, 8, LIMINE_MEMORY_LOADER);
    memcpy(ptr + ptrs_size, data, data_size);

    uint64_t *pointers = ptr;

    for (size_t i = 0; i < count; i++) {
        pointers[i] = boot_info.responses.hhdm.offset + phys + ptrs_size + i * entry_size;
    }

    return boot_info.responses.hhdm.offset + phys;
}
