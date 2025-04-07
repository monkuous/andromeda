#pragma once

#include "cpu/idt.h"
#include "mem/pmem.h"
#include <stddef.h>
#include <stdint.h>
#include "string.h"

#define PMAP_WRITABLE (1u << 1)

typedef struct {
    uint32_t page_dir_phys;
} pmap_t;

void init_pmap();

void create_pmap(pmap_t *pmap);
void free_pmap(pmap_t *pmap);
void clean_cur_pmap();
void switch_pmap(pmap_t *target);

void handle_page_fault(idt_frame_t *frame);

void pmap_map(uintptr_t virt, uint32_t phys, size_t size, uint32_t flags);
void pmap_alloc(uintptr_t virt, size_t size, uint32_t flags, bool anon);
void pmap_clone(pmap_t *out, uintptr_t virt, size_t size, bool cow);
void pmap_remap(uintptr_t virt, size_t size, uint32_t flags);
void pmap_unmap(uintptr_t virt, size_t size, bool skip_anon);

bool pmap_walk(uint32_t *phys_out, uintptr_t virt);

void *pmap_tmpmap(uint32_t phys);

static inline void copy_from_phys(void *out, uint32_t phys, size_t size) {
    while (size) {
        uint32_t pgoff = phys & PAGE_MASK;
        uint32_t pgrem = PAGE_SIZE - pgoff;
        if (pgrem > size) pgrem = size;

        memcpy(out, pmap_tmpmap(phys - pgoff) + pgoff, pgrem);

        out += pgrem;
        phys += pgrem;
        size -= pgrem;
    }
}
