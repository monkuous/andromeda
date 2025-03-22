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
