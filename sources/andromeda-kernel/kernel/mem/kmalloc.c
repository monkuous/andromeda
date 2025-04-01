#include "kmalloc.h"
#include "compiler.h"
#include "mem/pmap.h"
#include "mem/vmem.h"
#include <stddef.h>
#include <stdint.h>

struct free_obj {
    struct free_obj *next;
};

#define ZERO_PTR ((void *)_Alignof(max_align_t))
#define ORDER(x) (32 - __builtin_clzl((x) - 1))
#define MIN_ORDER ORDER(sizeof(struct free_obj))
#define MAX_ORDER 12
#define ALLOC_SIZE (1ul << MAX_ORDER)

static struct free_obj *objects[MAX_ORDER - MIN_ORDER + 1];

void *kmalloc(size_t size) {
    if (unlikely(!size)) return ZERO_PTR;

    if (size < sizeof(struct free_obj)) size = sizeof(struct free_obj);
    int order = ORDER(size);
    if (unlikely(order > MAX_ORDER)) return nullptr;

    struct free_obj *obj = objects[order - MIN_ORDER];

    if (likely(obj)) {
        objects[order - MIN_ORDER] = obj->next;
    } else {
        uintptr_t addr = vmem_alloc(ALLOC_SIZE);
        pmap_alloc(addr, ALLOC_SIZE, PMAP_WRITABLE, true);
        obj = (struct free_obj *)addr;

        if (order != MAX_ORDER) {
            size = 1ul << order;

            struct free_obj *last = obj;

            for (size_t off = size; off < ALLOC_SIZE; off += size) {
                struct free_obj *cur = (struct free_obj *)(addr + off);
                last->next = cur;
                last = cur;
            }

            last->next = nullptr;
            objects[order - MIN_ORDER] = obj->next;
        }
    }

    return obj;
}

void kfree(void *ptr, size_t size) {
    if (unlikely(!ptr)) return;
    if (unlikely(!size)) return;

    struct free_obj *obj = ptr;
    if (size < sizeof(struct free_obj)) size = sizeof(struct free_obj);
    int order = ORDER(size);

    obj->next = objects[order - MIN_ORDER];
    objects[order - MIN_ORDER] = obj;
}
