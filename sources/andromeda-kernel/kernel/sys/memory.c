#include "memory.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/pmap.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/exec.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/hash.h"
#include "util/list.h"
#include <andromeda/string.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>

int64_t sys_MMAP(uintptr_t hint, size_t len, int fprot, int fd, uint32_t off_low, uint32_t off_high) {
    if (unlikely(off_high & 0x80000000)) return -EINVAL;

    int flags = fprot & 0xfffffff;
    int prot = fprot >> 28;
    int error;
    file_t *file = nullptr;

    if (!(flags & MAP_ANON)) {
        error = -fd_lookup(&file, fd);
        if (unlikely(error)) return error;
    }

    error = -vm_map(&hint, len, flags, prot, file, ((uint64_t)off_high << 32) | off_low);
    if (file) file_deref(file);
    if (unlikely(error)) return error;

    return hint;
}

int sys_MUNMAP(uintptr_t addr, size_t size) {
    return -vm_unmap(addr, size);
}

typedef struct {
    list_node_t node;
    thread_t *thread;
    struct futex_addr *addr;
} futex_waiter_t;

struct futex_loc {
    uint64_t value;
    inode_t *inode;
    uint32_t hash;
};

struct futex_addr {
    struct futex_addr *prev;
    struct futex_addr *next;
    struct futex_loc location;
    list_t waiters;
};

static struct futex_addr **futexes;
static size_t futex_cap;
static size_t futex_cnt;

static int get_location(struct futex_loc *out, uintptr_t addr) {
    if (unlikely(addr & 3)) return EINVAL;

    int error = verify_pointer(addr, sizeof(int));
    if (unlikely(error)) return error;

    vm_region_t *region = vm_get_region(addr);
    if (unlikely(!region)) return EFAULT;

    out->inode = region->src->inode;

    if (out->inode) {
        // caller is responsible for increasing the inode ref count if necessary
        out->value = region->offset + (addr - region->head);
        goto exit;
    }

    if (region->flags & MAP_PRIVATE) {
        // anonymous MAP_PRIVATE mappings can get cow'd, but they can't be moved
        // or shared, so just use the virtual address as its identifier
        out->value = addr;
        goto exit;
    }

    // anonymous MAP_SHARED pages will maintain their physical address forever,
    // so we can use that as an identifier

    // make sure the page is faulted in
    int value;
    error = user_memcpy(&value, (const void *)addr, sizeof(value));
    if (unlikely(error)) return error;

    uint32_t phys;
    error = pmap_walk(&phys, addr);
    if (unlikely(error)) return error;

    out->value = phys;
exit:
    out->hash = make_hash_blob(out, sizeof(*out));
    return 0;
}

static struct futex_addr *get_addr(struct futex_loc *location) {
    if (!futex_cnt) return nullptr;

    size_t bucket = location->hash & (futex_cap - 1);
    struct futex_addr *cur = futexes[bucket];
    while (cur && memcmp(&cur->location, location, sizeof(*location))) cur = cur->next;
    return cur;
}

int sys_FUTEX_WAKE(uintptr_t addr) {
    struct futex_loc location;
    int error = -get_location(&location, addr);
    if (unlikely(error)) return error;

    struct futex_addr *faddr = get_addr(&location);
    if (!faddr) return 0;

    list_foreach(faddr->waiters, futex_waiter_t, node, waiter) {
        sched_unblock(waiter->thread);
    }

    return 0;
}

static void futex_cont(void *ptr) {
    futex_waiter_t *waiter = ptr;
    struct futex_addr *addr = waiter->addr;

    if (current->wake_reason == WAKE_INTERRUPT) {
        set_syscall_result(-EINTR);
    } else {
        set_syscall_result(0);
    }

    list_remove(&addr->waiters, &waiter->node);

    if (list_is_empty(&addr->waiters)) {
        size_t bucket = addr->location.hash & (futex_cap - 1);

        if (addr->prev) addr->prev->next = addr->next;
        else futexes[bucket] = addr->next;

        if (addr->next) addr->next->prev = addr->prev;

        if (addr->location.inode) inode_deref(addr->location.inode);
        vmfree(addr, sizeof(*addr));

        futex_cnt -= 1;
    }

    vmfree(waiter, sizeof(*waiter));
}

static void maybe_expand() {
    if (futex_cnt >= (futex_cap - (futex_cap / 4))) {
        size_t new_cap = futex_cap ? futex_cap * 2 : 8;
        size_t new_size = new_cap * sizeof(*futexes);
        struct futex_addr **new_table = vmalloc(new_size);
        memset(new_table, 0, new_size);

        for (size_t i = 0; i < futex_cap; i++) {
            struct futex_addr *cur = futexes[i];

            while (cur) {
                struct futex_addr *next = cur->next;

                size_t bucket = cur->location.hash & (new_cap - 1);
                cur->prev = nullptr;
                cur->next = new_table[bucket];
                if (cur->next) cur->next->prev = cur;
                new_table[bucket] = cur;

                cur = next;
            }
        }

        vmfree(futexes, futex_cap * sizeof(*futexes));
        futexes = new_table;
        futex_cap = new_cap;
    }
}

int sys_FUTEX_WAIT(uintptr_t addr, int expected, uint32_t, uint32_t, int32_t) {
    struct futex_loc loc;
    int error = -get_location(&loc, addr);
    if (unlikely(error)) return error;

    error = -verify_pointer(addr, sizeof(int));
    if (unlikely(error)) return error;

    int value;
    error = -user_memcpy(&value, (const void *)addr, sizeof(value));
    if (unlikely(error)) return error;

    if (value == expected) return -EAGAIN;

    struct futex_addr *faddr = get_addr(&loc);

    if (!faddr) {
        maybe_expand();
        size_t bucket = loc.hash & (futex_cap - 1);
        faddr = vmalloc(sizeof(*faddr));
        *faddr = (struct futex_addr){
                .prev = nullptr,
                .next = futexes[bucket],
                .location = loc,
        };
        if (faddr->next) faddr->next->prev = faddr;
        futexes[bucket] = faddr;
        futex_cnt += 1;

        if (faddr->location.inode) inode_ref(faddr->location.inode);
    }

    futex_waiter_t *waiter = vmalloc(sizeof(*waiter));
    waiter->thread = current;
    waiter->addr = faddr;
    list_insert_tail(&faddr->waiters, &waiter->node);

    // TODO: Timeouts
    sched_block(futex_cont, waiter, true);
    return -EAGAIN;
}

int sys_EXEC(int fd, uintptr_t argv, size_t narg, uintptr_t envp, size_t nenv) {
    int error = -verify_pointer(argv, narg * sizeof(andromeda_tagged_string_t));
    if (unlikely(error)) return error;

    error = -verify_pointer(envp, nenv * sizeof(andromeda_tagged_string_t));
    if (unlikely(error)) return error;

    file_t *file;
    error = -fd_lookup(&file, fd);
    if (unlikely(error)) return error;

    error = -execute(file, (const void *)argv, narg, (const void *)envp, nenv, true);
    file_deref(file);
    return error;
}

int sys_MPROTECT(uintptr_t addr, size_t size, int prot) {
    return -vm_remap(addr, size, prot);
}
