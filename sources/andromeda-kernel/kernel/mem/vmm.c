#include "vmm.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/layout.h"
#include "mem/pmap.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/sched.h"
#include "string.h"
#include "util/container.h"
#include "util/list.h"
#include "util/panic.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>

static void replace_child(vm_t *vm, vm_region_t *parent, vm_region_t *from, vm_region_t *to) {
    to->parent = parent;

    if (parent) {
        if (parent->left == from) {
            parent->left = to;
        } else {
            parent->right = to;
        }
    } else {
        vm->regtree = to;
    }
}

static vm_region_t *rotate_left(vm_t *vm, vm_region_t *root, vm_region_t *right) {
    vm_region_t *parent = root->parent;

    vm_region_t *new_right = right->left;
    root->right = new_right;
    if (new_right) new_right->parent = root;

    right->left = root;
    root->parent = right;

    if (right->balance == 0) {
        root->balance = 1;
        right->balance = -1;
    } else {
        root->balance = 0;
        right->balance = 0;
    }

    replace_child(vm, parent, root, right);
    return right;
}

static vm_region_t *rotate_right(vm_t *vm, vm_region_t *root, vm_region_t *left) {
    vm_region_t *parent = root->parent;

    vm_region_t *new_left = left->right;
    root->left = new_left;
    if (new_left) new_left->parent = root;

    left->right = root;
    root->parent = left;

    if (left->balance == 0) {
        root->balance = -1;
        left->balance = 1;
    } else {
        root->balance = 0;
        left->balance = 0;
    }

    replace_child(vm, parent, root, left);
    return left;
}

static vm_region_t *rotate_left_right(vm_t *vm, vm_region_t *root, vm_region_t *left) {
    vm_region_t *parent = root->parent;
    vm_region_t *new_root = left->right;

    vm_region_t *new_left_right = new_root->left;
    left->right = new_left_right;
    if (new_left_right) new_left_right->parent = left;

    new_root->left = left;
    left->parent = new_root;

    vm_region_t *new_right_left = new_root->right;
    root->left = new_right_left;
    if (new_right_left) new_right_left->parent = root;

    new_root->right = root;
    root->parent = new_root;

    if (new_root->balance == 0) {
        root->balance = 0;
        left->balance = 0;
    } else if (new_root->balance > 0) {
        root->balance = 1;
        left->balance = 0;
    } else {
        root->balance = 0;
        left->balance = -1;
    }

    new_root->balance = 0;
    replace_child(vm, parent, root, new_root);
    return new_root;
}

static vm_region_t *rotate_right_left(vm_t *vm, vm_region_t *root, vm_region_t *right) {
    vm_region_t *parent = root->parent;
    vm_region_t *new_root = right->left;

    vm_region_t *new_right_left = new_root->right;
    right->left = new_right_left;
    if (new_right_left) new_right_left->parent = right;

    new_root->right = right;
    right->parent = new_root;

    vm_region_t *new_left_right = new_root->left;
    root->right = new_left_right;
    if (new_left_right) new_left_right->parent = root;

    new_root->left = root;
    root->parent = new_root;

    if (new_root->balance == 0) {
        root->balance = 0;
        right->balance = 0;
    } else if (new_root->balance > 0) {
        root->balance = -1;
        right->balance = 0;
    } else {
        root->balance = 0;
        right->balance = 1;
    }

    new_root->balance = 0;
    replace_child(vm, parent, root, new_root);
    return new_root;
}

static void tree_add(vm_t *vm, vm_region_t *region) {
    vm_region_t *parent = NULL;
    vm_region_t **field = &vm->regtree;
    vm_region_t *cur = *field;

    // find location to insert at
    while (cur) {
        if (region->head <= cur->head) {
            field = &cur->left;
        } else {
            field = &cur->right;
        }

        parent = cur;
        cur = *field;
    }

    // perform insertion
    region->parent = parent;
    region->left = NULL;
    region->right = NULL;
    region->balance = 0;
    *field = region;

    // rebalance tree
    while (parent) {
        if (region == parent->left) {
            parent->balance -= 1;

            if (parent->balance == -2) {
                if (region->balance > 0) {
                    parent = rotate_left_right(vm, parent, region);
                } else {
                    parent = rotate_right(vm, parent, region);
                }
            }
        } else {
            parent->balance += 1;

            if (parent->balance == 2) {
                if (region->balance < 0) {
                    parent = rotate_right_left(vm, parent, region);
                } else {
                    parent = rotate_left(vm, parent, region);
                }
            }
        }

        if (parent->balance == 0) break;

        region = parent;
        parent = parent->parent;
    }
}

static void tree_del(vm_t *vm, vm_region_t *region) {
retry: {
    vm_region_t *parent = region->parent;
    vm_region_t **field;

    if (parent) {
        if (region == parent->left) field = &parent->left;
        else field = &parent->right;
    } else {
        field = &vm->regtree;
    }

    if (!region->left && !region->right) {
        *field = NULL;
    } else if (!region->left) {
        *field = region->right;
        (*field)->parent = parent;
    } else if (!region->right) {
        *field = region->left;
        (*field)->parent = parent;
    } else {
        // swap with successor and retry
        vm_region_t *successor = region->right;
        while (successor->left) successor = successor->left;

        vm_region_t *orig_right = successor->right;
        int orig_balance = successor->balance;

        successor->left = region->left;
        successor->left->parent = successor;
        successor->balance = region->balance;

        if (region->right != successor) {
            successor->right = region->right;

            successor->parent->left = region;
            region->parent = successor->parent;
        } else {
            successor->right = region;
        }

        successor->right->parent = successor;
        successor->parent = parent;

        region->left = NULL;
        region->right = orig_right;
        if (region->right) region->right->parent = region;
        region->balance = orig_balance;

        *field = successor;
        goto retry;
    }

    // rebalance tree

    while (parent != NULL) {
        if (field == &parent->left) {
            parent->balance += 1;

            if (parent->balance == 2) {
                vm_region_t *right = parent->right;

                if (right->balance < 0) {
                    parent = rotate_right_left(vm, parent, right);
                } else {
                    parent = rotate_left(vm, parent, right);
                }
            }
        } else {
            parent->balance -= 1;

            if (parent->balance == -2) {
                vm_region_t *left = parent->left;

                if (left->balance > 0) {
                    parent = rotate_left_right(vm, parent, left);
                } else {
                    parent = rotate_right(vm, parent, left);
                }
            }
        }

        if (parent->balance != 0) break;

        parent = parent->parent;
    }
}
}

static bool is_tree_location_valid(vm_region_t *region, uintptr_t new_head) {
    if (region->parent) {
        if (region == region->parent->left) {
            if (new_head > region->parent->head) return false;
        } else if (new_head <= region->parent->head) {
            return false;
        }
    }

    if (region->left && new_head < region->left->head) return false;
    if (region->right && new_head >= region->right->head) return false;

    return true;
}

static void tree_mov(vm_t *vm, vm_region_t *region, uintptr_t new_head) {
    if (!is_tree_location_valid(region, new_head)) {
        tree_del(vm, region);
        region->head = new_head;
        tree_add(vm, region);
    } else {
        region->head = new_head;
    }
}

vm_t *vm_create() {
    vm_t *vm = vmalloc(sizeof(*vm));
    memset(vm, 0, sizeof(*vm));
    vm->references = 1;
    create_pmap(&vm->pmap);
    return vm;
}

static vm_region_t *clone_region(vm_t *dvm, vm_region_t *src) {
    vm_region_t *dst = vmalloc(sizeof(*dst));
    memset(dst, 0, sizeof(*dst));

    dst->vm = dvm;
    dst->head = src->head;
    dst->tail = src->tail;
    dst->flags = src->flags;
    dst->prot = src->prot;
    dst->src = src->src;
    dst->offset = src->offset;

    if (dst->src) {
        file_ref(dst->src);
        list_insert_tail(&dst->src->inode->data.mappings, &dst->snode);
    }

    pmap_clone(&dvm->pmap, dst->head, dst->tail - dst->head + 1, dst->flags & MAP_PRIVATE);

    return dst;
}

static void clone_regions(vm_t *dst) {
    vm_region_t *scur = current->vm->regtree;
    if (!scur) return;

    vm_region_t *dcur = NULL;
    int prev_relation = 0; // -1 = ascended from left subtree, 0 = descended, 1 = ascended from right subtree

    vm_region_t *last = NULL;

    for (;;) {
        // get or create dcur
        if (prev_relation == 0) {
            vm_region_t *dreg = clone_region(dst, scur);

            dreg->balance = scur->balance;

            if (dcur) {
                dreg->parent = dcur;

                if (dreg->head < dcur->head) {
                    dcur->left = dreg;
                } else {
                    dcur->right = dreg;
                }
            } else {
                dst->regtree = dreg;
            }

            dcur = dreg;
        } else {
            dcur = dcur->parent;
        }

        // add to the region list if ascended from left subtree or descended into the leftmost node of its subtree
        if (prev_relation < 0 || (prev_relation == 0 && !scur->left)) {
            list_insert_after(&dst->regions, &last->node, &dcur->node);
            last = dcur;
        }

        // traverse
        if (prev_relation == 0 && scur->left) {
            scur = scur->left;
            continue;
        }

        if (prev_relation <= 0 && scur->right) {
            scur = scur->right;
            prev_relation = 0;
            continue;
        }

        if (scur->parent) {
            if (scur == scur->parent->left) prev_relation = -1;
            else prev_relation = 1;

            scur = scur->parent;
            continue;
        }

        break;
    }
}

vm_t *vm_clone() {
    vm_t *vm = vm_create();
    clone_regions(vm);
    return vm;
}

void vm_free(vm_t *vm) {
    free_pmap(&vm->pmap);

    vm_region_t *cur = container(vm_region_t, node, vm->regions.first);

    while (cur) {
        vm_region_t *next = container(vm_region_t, node, cur->node.next);

        if (cur->src) {
            list_remove(&cur->src->inode->data.mappings, &cur->snode);
            file_deref(cur->src);
        }

        vmfree(cur, sizeof(*cur));
        cur = next;
    }

    vmfree(vm, sizeof(*vm));
}

static void get_nonoverlap_bounds(
        vm_t *vm,
        uintptr_t head,
        uintptr_t tail,
        vm_region_t **prev_out,
        vm_region_t **next_out
) {
    vm_region_t *prev = NULL;
    vm_region_t *next = container(vm_region_t, node, vm->regions.first);

    while (next && next->tail < head) {
        prev = next;
        next = container(vm_region_t, node, next->node.next);
    }

    while (next && next->head <= tail) {
        next = container(vm_region_t, node, next->node.next);
    }

    *prev_out = prev;
    *next_out = next;
}

static vm_region_t *get_next(vm_t *vm, vm_region_t *prev) {
    return container(vm_region_t, node, prev ? prev->node.next : vm->regions.first);
}

#define SHARED_WRITE (HYDROGEN_MEM_SHARED | HYDROGEN_MEM_WRITE)

static void process_unmap(uintptr_t head, uintptr_t tail) {
    pmap_unmap(head, tail - head + 1, false);
}

static int remove_overlapping_regions(
        vm_t *vm,
        vm_region_t **prev_inout,
        vm_region_t **next_inout,
        uintptr_t head,
        uintptr_t tail
) {
    vm_region_t *prev = *prev_inout;
    vm_region_t *next = *next_inout;

    vm_region_t *cur = get_next(vm, prev);

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into two
            ASSERT(cur->node.prev == &prev->node);
            ASSERT(cur->node.next == &next->node);
            process_unmap(head, tail);

            vm_region_t *nreg = vmalloc(sizeof(*nreg));
            memset(nreg, 0, sizeof(*nreg));

            nreg->vm = vm;
            nreg->head = tail + 1;
            nreg->tail = cur->tail;
            nreg->flags = cur->flags;
            nreg->prot = cur->prot;
            nreg->src = cur->src;
            nreg->offset = cur->offset + (nreg->head - cur->head);

            if (cur->src) {
                file_ref(cur->src);
                list_insert_tail(&cur->src->inode->data.mappings, &nreg->snode);
            }

            cur->tail = head - 1;
            tree_add(vm, nreg);
            list_insert_after(&vm->regions, &cur->node, &nreg->node);

            *prev_inout = cur;
            *next_inout = nreg;
            return 0;
        } else if (cur->head < head) {
            // Needs to be truncated
            ASSERT(cur->node.prev == &prev->node);
            process_unmap(head, cur->tail);

            cur->tail = head - 1;

            *prev_inout = cur;
            cur = container(vm_region_t, node, cur->node.next);
        } else if (cur->tail > tail) {
            // Needs to be truncated and moved
            ASSERT(cur->node.next == &next->node);
            process_unmap(cur->head, tail);

            tree_mov(vm, cur, tail + 1);

            *next_inout = cur;
            return 0;
        } else {
            // Needs to be completely removed
            process_unmap(cur->head, cur->tail);

            vm_region_t *n = container(vm_region_t, node, cur->node.next);

            tree_del(vm, cur);
            list_remove(&vm->regions, &cur->node);

            if (cur->src) {
                list_remove(&cur->src->inode->data.mappings, &cur->snode);
                file_deref(cur->src);
            }

            vmfree(cur, sizeof(*cur));

            cur = n;
        }
    }

    return 0;
}

static bool can_merge(vm_region_t *r1, vm_region_t *r2) {
    if (!r1 || !r2) return false;
    ASSERT(r1->head < r2->head);

    if (r1->tail + 1 != r2->head) return false;
    if (r1->flags != r2->flags) return false;
    if (r1->prot != r2->prot) return false;
    if (r1->src != r2->src) return false;
    if (r1->src && r1->offset + (r2->head - r1->head) != r2->offset) return false;

    return true;
}

// might free `region`
static void merge_or_insert(vm_t *vm, vm_region_t *prev, vm_region_t *next, vm_region_t *region) {
    bool prev_merge = can_merge(prev, region);
    bool next_merge = can_merge(region, next);

    if (prev_merge && next_merge) {
        prev->tail = next->tail;

        tree_del(vm, next);
        list_remove(&vm->regions, &next->node);

        if (prev->src) {
            // both can merge with prev, so prev->src == region->src == next->src
            list_remove(&prev->src->inode->data.mappings, &region->snode);
            list_remove(&prev->src->inode->data.mappings, &next->snode);
            file_deref(prev->src);
            file_deref(prev->src);
        }

        vmfree(region, sizeof(*region));
        vmfree(next, sizeof(*next));
    } else if (prev_merge) {
        prev->tail = region->tail;

        if (prev->src) {
            list_remove(&prev->src->inode->data.mappings, &region->snode);
            file_deref(prev->src);
        }

        vmfree(region, sizeof(*region));
    } else if (next_merge) {
        tree_mov(vm, next, region->head);

        if (next->src) {
            list_remove(&next->src->inode->data.mappings, &region->snode);
            file_deref(next->src);
        }

        vmfree(region, sizeof(*region));
    } else {
        tree_add(vm, region);
        list_insert_after(&vm->regions, &prev->node, &region->node);
    }
}

static int check_prot(file_t *file, int flags, int prot) {
    int avail_prot;

    switch (file->flags & O_ACCMODE) {
    case O_RDONLY: avail_prot = PROT_READ | PROT_EXEC; break;
    case O_WRONLY: return EACCES;
    case O_RDWR: avail_prot = PROT_READ | PROT_WRITE | PROT_EXEC; break;
    default: UNREACHABLE();
    }

    if ((flags & MAP_SHARED) && (prot & ~avail_prot)) return EACCES;

    return 0;
}

static int do_map(
        vm_t *vm,
        uintptr_t head,
        uintptr_t tail,
        int flags,
        int prot,
        file_t *file,
        size_t offset,
        vm_region_t *prev,
        vm_region_t *next
) {
    vm_region_t *region = vmalloc(sizeof(*region));
    memset(region, 0, sizeof(*region));

    region->vm = vm;
    region->head = head;
    region->tail = tail;
    region->flags = flags & ~MAP_FIXED;
    region->prot = prot;
    region->offset = offset;

    if (file) {
        region->src = file;

        int error = check_prot(file, flags, prot);
        if (unlikely(error)) {
            vmfree(region, sizeof(*region));
            return EACCES;
        }
    }

    int error = remove_overlapping_regions(vm, &prev, &next, head, tail);
    if (unlikely(error)) {
        vmfree(region, sizeof(*region));
        return error;
    }

    if (file) {
        file_ref(file);
        list_insert_tail(&file->inode->data.mappings, &region->snode);
    }

    merge_or_insert(vm, prev, next, region);

    if (file && file->ops->mmap && prot != PROT_NONE) {
        file->ops->mmap(file, head, tail, offset, flags, prot);
    }

    return 0;
}

static int do_map_exact(vm_t *vm, uintptr_t head, size_t size, int flags, int prot, file_t *file, size_t offset) {
    uintptr_t tail = head + (size - 1);
    if (tail < head) return EINVAL;
    if (head < PAGE_SIZE || tail >= KERN_VIRT_BASE) return EINVAL;

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(vm, head, tail, &prev, &next);

    return do_map(vm, head, tail, flags, prot, file, offset, prev, next);
}

static uintptr_t get_tail(vm_region_t *region) {
    return region ? region->tail : PAGE_MASK;
}

static uintptr_t get_head(vm_region_t *region) {
    return region ? region->head : KERN_VIRT_BASE;
}

static int find_map_location(
        vm_t *vm,
        size_t size,
        vm_region_t **prev_out,
        vm_region_t **next_out,
        uintptr_t *head_out,
        uintptr_t *tail_out
) {
    vm_region_t *prev = NULL;
    vm_region_t *next = container(vm_region_t, node, vm->regions.first);

    for (;;) {
        size_t avail = get_head(next) - get_tail(prev) + 1;
        if (avail >= size) break;

        if (!next) return ENOMEM;

        prev = next;
        next = container(vm_region_t, node, next->node.next);
    }

    uintptr_t head = get_tail(prev) + 1;
    uintptr_t tail = head + (size - 1);

    *prev_out = prev;
    *next_out = next;
    *head_out = head;
    *tail_out = tail;

    return 0;
}

int vm_map(uintptr_t *addr, size_t size, int flags, int prot, file_t *file, uint64_t offset) {
    uintptr_t wanted = *addr;
    if (unlikely((wanted | size | offset) & PAGE_MASK)) return EINVAL;
    if (unlikely(!size)) return EINVAL;
    if (unlikely(flags & ~(MAP_SHARED | MAP_PRIVATE | MAP_FIXED | MAP_ANON))) return EINVAL;
    if (unlikely(!(flags & (MAP_SHARED | MAP_PRIVATE)))) return EINVAL;
    if (unlikely((flags & (MAP_SHARED | MAP_PRIVATE)) == (MAP_SHARED | MAP_PRIVATE))) return EINVAL;
    if (unlikely(prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))) return EINVAL;

    if (file) {
        if (unlikely(flags & MAP_ANON)) return EINVAL;
        if (unlikely(!file->ops)) return EBADF;
        if (unlikely(!S_ISREG(file->inode->mode) && !file->ops->mmap)) return ENODEV;
    } else if (unlikely(!(flags & MAP_ANON))) {
        return EINVAL;
    }

    vm_t *vm = current->vm;

    int error = do_map_exact(vm, wanted, size, flags, prot, file, offset);
    if (!error || (flags & MAP_FIXED)) return error;

    vm_region_t *prev, *next;
    uintptr_t head, tail;
    error = find_map_location(vm, size, &prev, &next, &head, &tail);

    if (likely(!error)) {
        error = do_map(vm, head, tail, flags, prot, file, offset, prev, next);

        if (likely(!error)) {
            *addr = head;
        }
    }

    return error;
}

static void alloc_extra(vm_region_t **ptr) {
    *ptr = vmalloc(sizeof(**ptr));
    memset(*ptr, 0, sizeof(**ptr));
}

static int do_remap(vm_t *vm, vm_region_t *prev, vm_region_t *next, uintptr_t head, uintptr_t tail, int prot) {
    vm_region_t *regions[2];
    vm_region_t *cur = get_next(vm, prev);
    size_t extra_regions = 0;

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->prot != prot) {
            if (cur->head < head) alloc_extra(&regions[extra_regions++]);
            if (cur->tail > tail) alloc_extra(&regions[extra_regions++]);

            if (cur->src) {
                int error = check_prot(cur->src, cur->flags, cur->prot);

                if (unlikely(error)) {
                    for (size_t i = 0; i < extra_regions; i++) {
                        vmfree(regions[i], sizeof(*regions[i]));
                    }

                    return error;
                }
            }
        }

        cur = container(vm_region_t, node, cur->node.next);
    }

    ASSERT(extra_regions <= 2);

    cur = get_next(vm, prev);

    // No errors allowed from now on

    while (cur != next) {
        ASSERT(cur);
        ASSERT(cur->head <= tail && cur->tail >= head);

        if (cur->prot == prot) {
            cur = container(vm_region_t, node, cur->node.next);
            continue;
        }

        vm_region_t *region;

        if (cur->head < head && cur->tail > tail) {
            // Needs to be split into three
            ASSERT(extra_regions == 2);
            ASSERT(cur->node.prev == &prev->node);
            ASSERT(cur->node.next == &next->node);

            regions[0]->vm = vm;
            regions[0]->head = head;
            regions[0]->tail = tail;
            regions[0]->flags = cur->flags;
            regions[0]->prot = cur->prot;
            regions[0]->src = cur->src;
            regions[0]->offset = cur->offset + (head - cur->head);

            regions[1]->vm = vm;
            regions[1]->head = tail + 1;
            regions[1]->tail = cur->tail;
            regions[1]->flags = cur->flags;
            regions[1]->prot = cur->prot;
            regions[1]->src = cur->src;
            regions[1]->offset = cur->offset + (tail + 1 - cur->head);

            if (cur->src) {
                file_ref(cur->src);
                file_ref(cur->src);
                list_insert_tail(&cur->src->inode->data.mappings, &regions[0]->snode);
                list_insert_tail(&cur->src->inode->data.mappings, &regions[1]->snode);
            }

            cur->tail = head - 1;
            tree_add(vm, regions[0]);
            tree_add(vm, regions[1]);
            list_insert_after(&vm->regions, &cur->node, &regions[0]->node);
            list_insert_after(&vm->regions, &regions[0]->node, &regions[1]->node);

            region = regions[0];
            cur = regions[1];

            extra_regions -= 2;
        } else if (cur->head < head) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(cur->node.prev == &prev->node);

            region = regions[--extra_regions];

            region->vm = vm;
            region->head = head;
            region->tail = cur->tail;
            region->flags = cur->flags;
            region->prot = cur->prot;
            region->src = cur->src;
            region->offset = cur->offset + (head - cur->head);

            if (cur->src) {
                file_ref(cur->src);
                list_insert_tail(&cur->src->inode->data.mappings, &region->snode);
            }

            cur->tail = head - 1;
            tree_add(vm, region);
            list_insert_after(&vm->regions, &cur->node, &region->node);
        } else if (cur->tail > tail) {
            // Needs to be split into two
            ASSERT(extra_regions >= 1);
            ASSERT(cur->node.next == &next->node);

            region = cur;
            cur = regions[--extra_regions];

            cur->vm = vm;
            cur->head = tail + 1;
            cur->tail = region->tail;
            cur->flags = region->flags;
            cur->prot = region->prot;
            cur->src = region->src;
            cur->offset = region->offset + (cur->head - region->head);

            if (cur->src) {
                file_ref(cur->src);
                list_insert_tail(&cur->src->inode->data.mappings, &cur->snode);
            }

            region->tail = tail;
            tree_add(vm, cur);
            list_insert_after(&vm->regions, &region->node, &cur->node);
        } else {
            region = cur;
        }

        int old_prot = region->prot;
        region->prot = prot;

        if (prot) {
            if (old_prot == PROT_NONE) {
                if (region->src && region->src->ops->mmap) {
                    region->src->ops
                            ->mmap(region->src, region->head, region->tail, region->offset, region->flags, region->prot
                            );
                }
            } else {
                pmap_remap(region->head, region->tail - region->head + 1, prot & PROT_WRITE ? PMAP_WRITABLE : 0);
            }
        } else {
            pmap_unmap(region->head, region->tail - region->head + 1, false);
        }

        cur = container(vm_region_t, node, cur->node.next);
    }

    ASSERT(extra_regions == 0);
    return 0;
}

int vm_remap(uintptr_t addr, size_t size, int prot) {
    if (unlikely((addr | size) & PAGE_MASK)) return EINVAL;
    if (unlikely(!size)) return EINVAL;
    if (unlikely(prot & ~(PROT_READ | PROT_WRITE | PROT_EXEC))) return EINVAL;

    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return EINVAL;
    if (addr < PAGE_SIZE || tail >= KERN_VIRT_BASE) return EINVAL;

    vm_t *vm = current->vm;

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(vm, addr, tail, &prev, &next);

    return do_remap(vm, prev, next, addr, tail, prot);
}

int vm_unmap(uintptr_t addr, size_t size) {
    if (unlikely((addr | size) & PAGE_MASK)) return EINVAL;
    if (unlikely(!size)) return EINVAL;

    uintptr_t tail = addr + (size - 1);
    if (tail < addr) return EINVAL;
    if (addr < PAGE_SIZE || tail >= KERN_VIRT_BASE) return EINVAL;

    vm_t *vm = current->vm;

    vm_region_t *prev, *next;
    get_nonoverlap_bounds(vm, addr, tail, &prev, &next);

    return remove_overlapping_regions(vm, &prev, &next, addr, tail);
}

vm_t *vm_join(vm_t *other) {
    vm_t *old = current->vm;
    current->vm = other;
    if (old != other) switch_pmap(likely(other) ? &other->pmap : nullptr);
    return old;
}

int vm_copy(void *dest, vm_t *srcvm, const void *src, size_t count) {
    unsigned char copy_buf[1024];

    while (count) {
        size_t cur = count < sizeof(copy_buf) ? count : sizeof(copy_buf);

        vm_t *orig = vm_join(srcvm);
        int error = user_memcpy(copy_buf, src, cur);
        vm_join(orig);
        if (unlikely(error)) return error;

        error = user_memcpy(dest, copy_buf, cur);
        if (unlikely(error)) return error;

        dest += cur;
        src += cur;
        count -= cur;
    }

    return 0;
}

vm_region_t *vm_get_region(uintptr_t addr) {
    vm_t *vm = current->vm;
    vm_region_t *cur = vm->regtree;

    while (cur && (addr < cur->head || addr > cur->tail)) {
        if (addr < cur->head) cur = cur->left;
        else cur = cur->right;
    }

    return cur;
}
