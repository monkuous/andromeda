#include "vmalloc.h"
#include "compiler.h"
#include "mem/kmalloc.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmem.h"
#include <stdint.h>

void *vmalloc(size_t size) {
    if (unlikely(size > PAGE_SIZE)) {
        size = (size + PAGE_MASK) & ~PAGE_MASK;

        uintptr_t addr = vmem_alloc(size);
        pmap_alloc(addr, size, PMAP_WRITABLE, true);
        return (void *)addr;
    }

    return kmalloc(size);
}

void vmfree(void *ptr, size_t size) {
    if (unlikely(!ptr)) return;
    if (unlikely(size > PAGE_SIZE)) {
        size = (size + PAGE_MASK) & ~PAGE_MASK;

        uintptr_t addr = (uintptr_t)ptr;
        pmap_unmap(addr, size);
        vmem_free(addr, size);
        return;
    }

    kfree(ptr, size);
}
