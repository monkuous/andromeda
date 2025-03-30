#pragma once

#include <stdint.h>

typedef enum {
    MEM_USABLE,
    MEM_ACPI_RECLAIM,
    MEM_ACPI_NVS,
    MEM_RESERVED,
} memory_type_t;

void bootmem_add(uint64_t base, uint64_t size, memory_type_t type);

uint32_t bootmem_alloc();
void bootmem_handover();

// if func returns false, iteration stops
// returns true if all entries have been iterated over, false if exited early
bool bootmem_iter(bool (*func)(uint64_t head, uint64_t tail, memory_type_t type, void *ctx), void *ctx, bool reverse);
