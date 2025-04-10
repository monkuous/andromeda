#pragma once

#include <andromeda/cpu.h>
#include <stddef.h>
#include <stdint.h>

// positive type values are reserved for libboot, negative ones reserved for protocol usage
#define LIBBOOT_MEMORY_USABLE 0
#define LIBBOOT_MEMORY_ACPI_RECLAIMABLE 1
#define LIBBOOT_MEMORY_ACPI_NVS 2
#define LIBBOOT_MEMORY_RESERVED 3

typedef uint64_t paddr_t;

typedef struct {
    paddr_t head;
    paddr_t tail;
    int type;
} libboot_mem_region_t;

#define LIBBOOT_MEM_CLONE_RAW_MMAP (1u << 0) // Clone the memory map from the raw memory map
#define LIBBOOT_MEM_MAINTAIN_MMAP (1u << 1)  // Adjust the memory map as necessary when allocating memory

bool libboot_mem_init(unsigned flags);

void libboot_mem_set_type(paddr_t head, paddr_t tail, int type);
const libboot_mem_region_t *libboot_mem_get_map(size_t *size_out);     // valid until the next libboot_mem_* call
const libboot_mem_region_t *libboot_mem_get_raw_map(size_t *size_out); // valid until the next libboot_mem_* call

// on entry, *phys should contain the highest allowed memory address
// `type` is ignored if `LIBBOOT_MEM_MAINTAIN_MMAP` isn't set
int libboot_mem_alloc_pages_fd(paddr_t *phys, size_t size, size_t align, int type);
void *libboot_mem_alloc_pages(paddr_t *phys, size_t size, size_t align, int type);

bool libboot_acpi_get_rsdp_addr(paddr_t *out);
bool libboot_acpi_get_rsdp(void **ptr_out, size_t *size_out);

void libboot_handover(andromeda_cpu_regs_t *regs);
