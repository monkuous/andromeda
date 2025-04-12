#pragma once

#include <stddef.h>
#include <stdint.h>

#define PAGE_WRITABLE 1
#define PAGE_EXECUTABLE 2
#define PAGE_FRAMEBUFFER 4

#define MIN_KERNEL_BASE_ADDR 0xffffffff80000000

extern uint32_t top_page_table_phys;
extern uint64_t min_higher_half_address;

void init_paging();
void paging_map(uint64_t virt, uint64_t phys, uint64_t size, int flags);
void paging_finalize();

uint64_t paging_resolve(uint64_t virt);
