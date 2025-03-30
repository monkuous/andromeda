#pragma once

#include <stddef.h>
#include <stdint.h>

#define PMAP_WRITABLE (1u << 1)

void init_pmap();

void pmap_map(uintptr_t virt, uint32_t phys, size_t size, uint32_t flags);
void pmap_alloc(uintptr_t virt, size_t size, uint32_t flags);
void pmap_unmap(uintptr_t virt, size_t size);

void *pmap_tmpmap(uint32_t phys);
