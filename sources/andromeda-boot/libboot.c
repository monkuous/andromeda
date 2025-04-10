#include "libboot.h"
#include "edid.h"
#include "utils.h"
#include <andromeda/cpu.h>
#include <andromeda/memory.h>
#include <andromeda/video.h>
#include <assert.h>
#include <dirent.h>
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

    bool ok = read_fully(fd, buf, size);
    int orig_errno = errno;
    close(fd);
    if (!ok) {
        free(buf);
        errno = orig_errno;
        return false;
    }

    ptr = buf;
    return true;
}

void libboot_handover(andromeda_cpu_regs_t *regs) {
    int cpu_fd = open("/dev/cpu", O_WRONLY);
    if (cpu_fd < 0) return;

    ioctl(cpu_fd, IOCTL_SET_REGISTERS, regs);
}

struct libboot_video_card {
    int fd;
    andromeda_video_mode_t *modes;
    ssize_t num_modes;
    void *edid;
    size_t edid_size;
    bool tried_edid;
};

static libboot_video_card_t *video_cards;
static size_t num_video_cards;

bool libboot_video_init(unsigned) {
    static bool did_init = false;
    if (did_init) return true;

    int dirfd = open("/dev/video", O_DIRECTORY | O_RDONLY);
    if (dirfd < 0) return false;

    DIR *dir = fdopendir(dirfd);
    if (!dir) {
        int orig_errno = errno;
        close(dirfd);
        errno = orig_errno;
        return false;
    }

    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            if (errno) goto cleanup;
            break;
        }

        if (entry->d_name[0] == '.') {
            if (entry->d_name[1] == 0 || (entry->d_name[1] == '.' && entry->d_name[2] == 0)) {
                continue;
            }
        }

        int fd = openat(dirfd, entry->d_name, O_RDWR);
        if (fd < 0) goto cleanup;

        size_t idx = num_video_cards++;
        video_cards = realloc(video_cards, num_video_cards * sizeof(*video_cards));
        memset(&video_cards[idx], 0, sizeof(*video_cards));
        video_cards[idx].fd = fd;
        video_cards[idx].num_modes = -1;
    }

    closedir(dir);
    did_init = true;
    return true;
cleanup:
    int orig_errno = errno;
    closedir(dir);

    for (size_t i = 0; i < num_video_cards; i++) {
        close(video_cards[i].fd);
        free(video_cards[i].modes);
    }

    free(video_cards);
    num_video_cards = 0;

    errno = orig_errno;
    return false;
}

bool libboot_video_get_console_fb(andromeda_framebuffer_t *out) {
    static andromeda_framebuffer_t fb;
    static bool have_fb;

    if (have_fb) {
        if (!fb.mode.pitch) {
            errno = ENOENT;
            return false;
        }

        *out = fb;
        return true;
    }

    int fd = open("/sys/console-framebuffer", O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) have_fb = true;
        return false;
    }

    bool ok = read_fully(fd, &fb, sizeof(fb));
    int orig_errno = errno;
    close(fd);
    if (!ok) {
        errno = orig_errno;
        return false;
    }

    have_fb = true;
    *out = fb;
    return true;
}

size_t libboot_video_num_cards() {
    return num_video_cards;
}

libboot_video_card_t *libboot_video_get_card(size_t idx) {
    assert(idx < num_video_cards);
    return &video_cards[idx];
}

ssize_t libboot_video_discover_modes(libboot_video_card_t *card) {
    if (card->num_modes >= 0) return card->num_modes;

    andromeda_video_modes_t buffer = {};
    int count = ioctl(card->fd, IOCTL_LIST_MODES, &buffer);
    if (count < 0) return -1;

    buffer.modes = malloc(count * sizeof(*buffer.modes));
    buffer.capacity = count;

    count = ioctl(card->fd, IOCTL_LIST_MODES, &buffer);
    if (count < 0) {
        int orig_errno = errno;
        free(buffer.modes);
        errno = orig_errno;
        return -1;
    }

    card->modes = buffer.modes;
    card->num_modes = count;
    return count;
}

const andromeda_video_mode_t *libboot_video_get_mode(libboot_video_card_t *card, size_t mode) {
    assert(card->num_modes >= 0);
    assert(mode < (size_t)card->num_modes);

    return &card->modes[mode];
}

static bool ensure_edid_available(libboot_video_card_t *card) {
    assert(card->num_modes >= 0);

    if (card->tried_edid) {
        if (card->edid) return true;
        errno = ENODATA;
        return false;
    }

    andromeda_edid_request_t request = {};
    int size = ioctl(card->fd, IOCTL_GET_EDID, &request);
    if (size < 0) {
        if (errno == ENODATA) card->tried_edid = true;
        return false;
    }

    request.buffer = malloc(size);
    request.capacity = size;

    size = ioctl(card->fd, IOCTL_GET_EDID, &request);
    if (size < 0) {
        int orig_errno = errno;
        free(request.buffer);
        errno = orig_errno;
        return false;
    }

    card->edid = request.buffer;
    card->edid_size = size;
    card->tried_edid = true;
    return true;
}

const void *libboot_video_get_edid_data(libboot_video_card_t *card, size_t *size_out) {
    if (!ensure_edid_available(card)) return nullptr;

    *size_out = card->edid_size;
    return card->edid;
}

ssize_t libboot_video_pick_mode(libboot_video_card_t *card, ssize_t wanted_width, ssize_t wanted_height) {
    if (wanted_width < 0 || wanted_height < 0) {
        if (ensure_edid_available(card)) {
            edid_t *edid = card->edid;

            if (wanted_width < 0) {
                wanted_width = edid->pref_timing.width_low | ((edid->pref_timing.width_hblank_high & 0xf0) << 4);
            }

            if (wanted_height < 0) {
                wanted_height = edid->pref_timing.height_low | ((edid->pref_timing.height_vblank_high & 0xf0) << 4);
            }
        } else if (errno != ENODATA) {
            return -1;
        } else {
            // If we don't know what to do for a given dimension, just pick the largest possible
            if (wanted_width < 0) wanted_width = SSIZE_MAX;
            if (wanted_height < 0) wanted_height = SSIZE_MAX;
        }
    }

    ssize_t candidate = -1;
    uint64_t cur_size_dist = UINT64_MAX;
    unsigned cur_depth = 0;

    for (ssize_t i = 0; i < card->num_modes; i++) {
        const andromeda_video_mode_t *mode = &card->modes[i];
        if (mode->memory_model != ANDROMEDA_MEMORY_MODEL_RGB) continue;

        // Pick the resolution closest to the one the user asked for
        ssize_t wdist = (ssize_t)mode->width - wanted_width;
        ssize_t hdist = (ssize_t)mode->height - wanted_height;
        uint64_t size_dist = (int64_t)wdist * wdist + (int64_t)hdist * hdist;

        if (size_dist > cur_size_dist) continue;
        if (size_dist == cur_size_dist && mode->bits_per_pixel < cur_depth) continue;

        candidate = i;
        cur_size_dist = size_dist;
        cur_depth = mode->bits_per_pixel;
    }

    if (candidate < 0) errno = ENODATA;
    return candidate;
}

int libboot_video_set_mode(libboot_video_card_t *card, andromeda_framebuffer_t *buf, size_t mode) {
    assert(card->num_modes >= 0);
    assert(mode < (size_t)card->num_modes);

    andromeda_framebuffer_request_t request = {.mode_index = mode};
    int fd = ioctl(card->fd, IOCTL_SET_MODE, &request);
    if (fd < 0) return -1;

    *buf = request.framebuffer;
    return fd;
}
