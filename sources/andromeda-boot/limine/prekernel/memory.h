#pragma once

#include <stddef.h>
#include <stdint.h>

uint32_t allocate_pages(size_t count);
void *allocate(size_t size);

void memory_cleanup();

void *tmpmap(uint64_t address, bool cache);
void copy_from_phys(void *dest, uint64_t address, size_t size, bool cache);
