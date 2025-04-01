#pragma once

#include "fs/vfs.h"
#include "mem/pmap.h"
#include "util/list.h"
#include <stdint.h>

typedef struct vm vm_t;
typedef struct vm_region vm_region_t;

struct vm_region {
    list_node_t node;
    vm_t *vm;
    vm_region_t *parent;
    vm_region_t *left;
    vm_region_t *right;
    uintptr_t head;
    uintptr_t tail;
    int balance;
    int flags : 28;
    int prot : 4;
    struct {
        inode_t *inode;
        int avail_prot;
    } src;
    list_node_t snode;
    size_t offset;
};

struct vm {
    size_t references;
    pmap_t pmap;
    vm_region_t *regtree;
    list_t regions;
};

vm_t *vm_create(void);
vm_t *vm_clone(void);
void vm_free(vm_t *vm);

int vm_map(uintptr_t *addr, size_t size, int flags, int prot, file_t *file, uint64_t offset);
int vm_remap(uintptr_t addr, size_t size, int prot);
int vm_unmap(uintptr_t addr, size_t size);

// returns the old vm
vm_t *vm_join(vm_t *other);

int vm_copy(void *dest, vm_t *srcvm, const void *src, size_t count);

vm_region_t *vm_get_region(uintptr_t addr);


