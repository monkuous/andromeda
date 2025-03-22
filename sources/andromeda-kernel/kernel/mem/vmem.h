#pragma once

#include <stddef.h>
#include <stdint.h>

void vmem_add_range(uintptr_t head, uintptr_t tail);

uintptr_t vmem_alloc(size_t size);
void vmem_free(uintptr_t addr, size_t size);
