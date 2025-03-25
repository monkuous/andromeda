#pragma once

#include <stddef.h>
#include <stdint.h>

#define PMAP_WRITABLE (1u << 1)

void pmap_alloc(uintptr_t virt, size_t size, uint32_t flags);
void pmap_unmap(uintptr_t virt, size_t size);
