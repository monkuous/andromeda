#include "requests.h"
#include "bootinfo.h"
#include "limine.h"
#include "main.h"
#include "utils.h"
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *request_names[REQUEST_MAX] = {
        [REQUEST_PAGING_MODE] = "paging mode",
        [REQUEST_STACK_SIZE] = "stack size",
        [REQUEST_HHDM] = "HHDM",
        [REQUEST_EXECUTABLE_ADDRESS] = "executable address",
        [REQUEST_ENTRY_POINT] = "entry point",
        [REQUEST_FRAMEBUFFER] = "framebuffer",
        [REQUEST_MEMORY_MAP] = "memory map",
        [REQUEST_RSDP] = "RSDP",
        [REQUEST_MODULE] = "modules",
        [REQUEST_EXECUTABLE_FILE] = "executable file",
        [REQUEST_EXECUTABLE_CMDLINE] = "executable command line",
        [REQUEST_SMP] = "multiprocessor"
};
static uint64_t request_ids[REQUEST_MAX][4] = {
        [REQUEST_PAGING_MODE] = LIMINE_PAGING_MODE_REQUEST,
        [REQUEST_STACK_SIZE] = LIMINE_STACK_SIZE_REQUEST,
        [REQUEST_HHDM] = LIMINE_HHDM_REQUEST,
        [REQUEST_EXECUTABLE_ADDRESS] = LIMINE_EXECUTABLE_ADDRESS_REQUEST,
        [REQUEST_ENTRY_POINT] = LIMINE_ENTRY_POINT_REQUEST,
        [REQUEST_FRAMEBUFFER] = LIMINE_FRAMEBUFFER_REQUEST,
        [REQUEST_MEMORY_MAP] = LIMINE_MEMMAP_REQUEST,
        [REQUEST_RSDP] = LIMINE_RSDP_REQUEST,
        [REQUEST_MODULE] = LIMINE_MODULE_REQUEST,
        [REQUEST_EXECUTABLE_FILE] = LIMINE_EXECUTABLE_FILE_REQUEST,
        [REQUEST_EXECUTABLE_CMDLINE] = LIMINE_EXECUTABLE_CMDLINE_REQUEST,
        [REQUEST_SMP] = LIMINE_MP_REQUEST,
};

static void *request_ptrs[REQUEST_MAX];

static void discard_found_requests() {
    for (int i = 0; i < REQUEST_MAX; i++) {
        request_ptrs[i] = nullptr;
    }
}

static int convert_request_id(uint64_t *id) {
    for (int i = 0; i < REQUEST_MAX; i++) {
        if (!memcmp(id, request_ids[i], sizeof(request_ids[i]))) {
            return i;
        }
    }

    return -1;
}

static void process_found_request(uint64_t *ptr) {
    static uint64_t common_magic[] = {LIMINE_COMMON_MAGIC};
    if (ptr[0] != common_magic[0] || ptr[1] != common_magic[1]) {
        fprintf(stderr, "%s: invalid request magic\n", progname);
        exit(1);
    }

    int idx = convert_request_id(ptr);

    if (idx >= 0) {
        if (request_ptrs[idx]) {
            fprintf(stderr,
                    "%s: found multiple %s requests (at offsets 0x%x and 0x%x)\n",
                    progname,
                    request_names[idx],
                    request_ptrs[idx] - kernel_image,
                    (void *)ptr - kernel_image);
            exit(1);
        }

        request_ptrs[idx] = ptr;
    } else {
        fprintf(stderr,
                "%s: warning: found unsupported request with id [0x%.16llx, 0x%.16llx]\n",
                progname,
                ptr[2],
                ptr[3]);
    }
}

static void find_requests() {
    static LIMINE_REQUESTS_START_MARKER;
    static LIMINE_REQUESTS_END_MARKER;
    static LIMINE_BASE_REVISION(0);
    static uint64_t common_magic[] = {LIMINE_COMMON_MAGIC};

    uint64_t *start_marker = nullptr;
    uint64_t *base_rev_ptr = nullptr;

    for (size_t i = 0; i < kernel_size; i += 8) {
        uint64_t *ptr = kernel_image + i;
        uint64_t avail = kernel_size - i;
        if (avail < 16) break;

        if (avail >= sizeof(limine_requests_start_marker) &&
            !memcmp(ptr, limine_requests_start_marker, sizeof(limine_requests_start_marker))) {
            if (start_marker) {
                fprintf(stderr,
                        "%s: warning: found multiple request start markers (at offsets 0x%x and 0x%x)\n",
                        progname,
                        (void *)start_marker - kernel_image,
                        (void *)ptr - kernel_image);
            }

            discard_found_requests();
            base_rev_ptr = nullptr;
            start_marker = ptr;
        }

        if (start_marker && avail >= sizeof(limine_requests_end_marker) &&
            !memcmp(ptr, limine_requests_end_marker, sizeof(limine_requests_end_marker))) {
            break;
        }

        if (avail >= sizeof(limine_base_revision) && ptr[0] == limine_base_revision[0] &&
            ptr[1] == limine_base_revision[1]) {
            if (base_rev_ptr) {
                fprintf(stderr,
                        "%s: found multiple base revision tags (at offsets 0x%x and 0x%x)\n",
                        progname,
                        (void *)base_rev_ptr - kernel_image,
                        (void *)ptr - kernel_image);
                exit(1);
            }

            base_rev_ptr = ptr;
            continue;
        }

        if (avail >= 32 && ptr[0] == common_magic[0] && ptr[1] == common_magic[1]) {
            process_found_request(ptr);
        }
    }

    if (base_rev_ptr) {
        base_revision = base_rev_ptr[2];

        if (base_revision <= MAX_BASE_REV) {
            base_rev_ptr[2] = 0;
        } else {
            base_revision = MAX_BASE_REV;
        }

        base_rev_ptr[1] = base_revision;
    }

    if (base_revision < MIN_BASE_REV) {
        fprintf(stderr, "%s: base revision %llu is unsupported\n", progname, base_revision);
        exit(1);
    }
}

void init_requests() {
    find_requests();
}

void *get_request(request_t request) {
    assert(request >= 0 && request < REQUEST_MAX);
    return request_ptrs[request];
}

void fill_response_pointers() {
    for (request_t i = 0; i < REQUEST_MAX; i++) {
        void *ptr = request_ptrs[i];
        if (!ptr) continue;

        switch (i) {
#define REQUEST(type, name)                                                                                            \
    case REQUEST_##type:                                                                                               \
        ((struct limine_##name##_request *)ptr)->response = boot_info.responses.hhdm.offset + boot_info_phys +         \
                                                            offsetof(boot_info_t, responses.name);                     \
        break;
            REQUEST(PAGING_MODE, paging_mode)
            REQUEST(STACK_SIZE, stack_size)
            REQUEST(HHDM, hhdm)
            REQUEST(EXECUTABLE_ADDRESS, executable_address)
            REQUEST(ENTRY_POINT, entry_point)
            REQUEST(FRAMEBUFFER, framebuffer)
            REQUEST(MEMORY_MAP, memmap)
            REQUEST(RSDP, rsdp)
            REQUEST(MODULE, module)
            REQUEST(EXECUTABLE_FILE, executable_file)
            REQUEST(EXECUTABLE_CMDLINE, executable_cmdline)
            // SMP request is intentionally left out, since that's pretty much entirely handled
            // by the prekernel, including setting the response pointer.
#undef REQUEST
        default: continue;
        }
    }
}
