#include "libboot.h"
#include <andromeda/cpu.h>
#include <andromeda/memory.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static int memfd = -1;

static libboot_mem_region_t *memory_map, *raw_memory_map;
static size_t mmap_count, raw_mmap_count;
static bool maintain_mmap;

bool libboot_mem_init(unsigned flags) {
    if (memfd >= 0) return true;

    int fd = open("/dev/mem", O_RDWR);
    if (fd < 0) return false;
    memfd = fd;

    FILE *file = fopen("/sys/memory-map", "r");

    for (;;) {
        paddr_t head, tail;
        char type_string[32];
        if (fscanf(file, "%llx-%llx %s", &head, &tail, type_string) < 3) {
            if (ferror(file)) {
                int orig_errno = errno;
                fclose(file);
                close(memfd);
                memfd = -1;
                free(raw_memory_map);
                raw_memory_map = nullptr;
                raw_mmap_count = 0;

                errno = orig_errno;
                return false;
            }

            break;
        }

        assert(head < tail);

        int type;

        if (!strcmp(type_string, "usable")) type = LIBBOOT_MEMORY_USABLE;
        else if (!strcmp(type_string, "acpi-reclaimable")) type = LIBBOOT_MEMORY_ACPI_RECLAIMABLE;
        else if (!strcmp(type_string, "acpi-nvs")) type = LIBBOOT_MEMORY_ACPI_NVS;
        else type = LIBBOOT_MEMORY_RESERVED; // unrecognized types become reserved

        size_t idx = raw_mmap_count++;

        if (idx > 0) {
            assert(raw_memory_map[idx - 1].tail < head);
        }

        raw_memory_map = realloc(raw_memory_map, raw_mmap_count * sizeof(*raw_memory_map));
        raw_memory_map[idx].head = head;
        raw_memory_map[idx].tail = tail;
        raw_memory_map[idx].type = type;
    }

    fclose(file);

    if (flags & LIBBOOT_MEM_CLONE_RAW_MMAP) {
        mmap_count = raw_mmap_count;
        size_t size = mmap_count * sizeof(*memory_map);
        memory_map = malloc(size);
        memcpy(memory_map, raw_memory_map, size);
    }

    maintain_mmap = flags & LIBBOOT_MEM_MAINTAIN_MMAP;

    return true;
}

static void remove_region(size_t i) {
    memmove(&memory_map[i], &memory_map[i + 1], (mmap_count - i - 1) * sizeof(*memory_map));
    mmap_count -= 1;
}

static size_t insert_region(size_t i, paddr_t head, paddr_t tail, int type) {
    bool prev_merge = i > 0 && memory_map[i - 1].type == type && memory_map[i - 1].tail + 1 == head;
    bool next_merge = i < mmap_count && memory_map[i].type == type && memory_map[i].head == tail + 1;

    if (prev_merge && next_merge) {
        memory_map[i - 1].tail = memory_map[i].tail;
        remove_region(i);
        return i - 1;
    } else if (prev_merge) {
        memory_map[i - 1].tail = tail;
        return i - 1;
    } else if (next_merge) {
        memory_map[i].head = head;
        return i;
    } else {
        mmap_count += 1;
        memory_map = realloc(memory_map, mmap_count * sizeof(*memory_map));
        memmove(&memory_map[i + 1], &memory_map[i], (mmap_count - i - 1) * sizeof(*memory_map));
        memory_map[i].head = head;
        memory_map[i].tail = tail;
        memory_map[i].type = type;
        return i;
    }
}

void libboot_mem_set_type(paddr_t head, paddr_t tail, int type) {
    size_t i = 0;

    while (i < mmap_count) {
        libboot_mem_region_t *region = &memory_map[i];
        paddr_t rhead = region->head;
        paddr_t rtail = region->tail;

        if (rtail < head) continue;
        if (rhead > tail) break;

        // rhead <= tail && head <= rtail -> overlap

        if (head < rhead) {
            i = insert_region(i, head, rhead - 1, type);
            head = rhead;
            continue;
        }

        paddr_t otail = tail < rtail ? tail : rtail;

        if (region->type != type) {
            if (rhead < head) {
                region->tail = head - 1;
                i += 1;
            } else {
                remove_region(i);
            }

            i = insert_region(i, head, otail, type);
        } else {
            i += 1;
        }

        if (otail == tail) return;
        head = otail + 1;
    }

    insert_region(i, head, tail, type);
}

const libboot_mem_region_t *libboot_mem_get_map(size_t *size_out) {
    *size_out = mmap_count;
    return memory_map;
}

const libboot_mem_region_t *libboot_mem_get_raw_map(size_t *size_out) {
    *size_out = raw_mmap_count;
    return raw_memory_map;
}

int libboot_mem_alloc_pages_fd(paddr_t *phys, size_t size, size_t align, int type) {
    size = (size + 0xfff) & ~0xfff;
    if (!size) {
        errno = EINVAL;
        return -1;
    }

    andromeda_pmalloc_t request = {
            .align = (align + 0xfff) & ~0xfff,
            .pages = size >> 12,
            .addr = *phys,
    };
    int fd = ioctl(memfd, IOCTL_PMALLOC, &request);
    if (fd < 0) return -1;

    if (maintain_mmap) libboot_mem_set_type(request.addr, request.addr + (size - 1), type);

    *phys = request.addr;
    return fd;
}

void *libboot_mem_alloc_pages(paddr_t *phys, size_t size, size_t align, int type) {
    int fd = libboot_mem_alloc_pages_fd(phys, size, align, type);
    if (fd < 0) return nullptr;

    void *addr = mmap(NULL, (size + 0xfff) & ~0xfff, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    int orig_errno = errno;
    close(fd);
    if (addr == MAP_FAILED) {
        errno = orig_errno;
        return nullptr;
    }

    return addr;
}

void libboot_mem_free_pages(void *ptr, size_t size) {
    munmap(ptr, (size + 0xfff) >> 12);
}

bool libboot_acpi_get_rsdp_addr(paddr_t *out) {
    static paddr_t addr = -1;
    if (addr != (paddr_t)-1) {
        *out = addr;
        return true;
    }

    FILE *file = fopen("/sys/acpi-rsdp-addr", "r");
    if (!file) return 1;
    bool status = fscanf(file, "%llx", &addr) != 0;
    fclose(file);
    *out = addr;
    return status;
}

bool libboot_acpi_get_rsdp(void **ptr_out, size_t *size_out) {
    static void *ptr = nullptr;
    static size_t size = 0;

    if (ptr) {
        *ptr_out = ptr;
        *size_out = size;
        return true;
    }

    int fd = open("/sys/acpi-rsdp", O_RDONLY);
    if (fd < 0) return false;

    struct stat stat;
    if (fstat(fd, &stat)) return false;

    size = stat.st_size;
    void *buf = malloc(size);

    size_t off = 0;
    while (off < size) {
        ssize_t wanted = size - off;
        ssize_t actual = read(fd, buf + off, wanted);
        if (actual < 0) {
            free(buf);
            return false;
        }
        if (!actual) break;

        off += actual;
    }

    ptr = buf;
    size = off;
    return true;
}

void libboot_handover(andromeda_cpu_regs_t *regs) {
    int cpu_fd = open("/dev/cpu", O_WRONLY);
    if (cpu_fd < 0) return;

    ioctl(cpu_fd, IOCTL_SET_REGISTERS, regs);
}
