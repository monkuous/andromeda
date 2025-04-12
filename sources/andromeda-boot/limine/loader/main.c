#include "main.h"
#include "cpufeat.h"
#include "framebuffer.h"
#include "hhdm.h"
#include "image.h"
#include "libboot.h"
#include "limine.h"
#include "memmap.h"
#include "memory.h"
#include "module.h"
#include "paging.h"
#include "requests.h"
#include "rsdp.h"
#include "utils.h"
#include <andromeda/cpu.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

extern const void prekernel_start, prekernel_end;

const char *progname;

void *kernel_image;
size_t kernel_size;
uint64_t base_revision;
boot_info_t boot_info = {
        .gdt =
                {
                        [1] = 0x00009b000000ffff,
                        [2] = 0x000093000000ffff,
                        [3] = 0x00cf9b000000ffff,
                        [4] = 0x00cf93000000ffff,
                        [5] = 0x00209b0000000000,
                        [6] = 0x0040930000000000,
                },
};
uint64_t boot_info_phys;

uint32_t kernel_cr4_value = 0x20;   /* PAE */
uint64_t kernel_efer_value = 0x100; /* LME */

ssize_t user_width = -1, user_height = -1;
const char *kernel_path;
const char *cmdline;

static uint32_t load_prekernel() {
    size_t size = *(uint32_t *)&prekernel_start;
    paddr_t addr = UINT32_MAX;
    void *ptr = alloc_pages(&addr, size, 0x1000, LIMINE_MEMORY_LOADER);
    memcpy(ptr, &prekernel_start, &prekernel_end - &prekernel_start);
    return addr + 4;
}

int main(int argc, char *argv[]) {
    progname = argv[0];

    module_t *last_module = nullptr;

    int c;
    while ((c = getopt(argc, argv, "hm:s:W:H:")) != -1) {
        switch (c) {
        case 'h':
            printf("usage: %s [OPTION...] EXECUTABLE [CMDLINE]\n"
                   "\n"
                   "options:\n"
                   "  -h        show this help message\n"
                   "  -m FILE   load FILE as a module\n"
                   "  -s STRING pass STRING to the last specified module\n"
                   "  -W NUM    try to pick a video mode with a width of NUM pixels\n"
                   "  -H NUM    try to pick a video mode with a height of NUM pixels\n",
                   progname);
            return 0;
        case 'm': last_module = add_module(optarg); break;
        case 's':
            if (!last_module) {
                fprintf(stderr, "%s: -s must be preceded by -m\n", progname);
                return 1;
            }
            set_module_string(last_module, optarg);
            break;
        case 'W': {
            char *end;
            user_width = strtol(optarg, &end, 10);
            if (*end) {
                fprintf(stderr, "%s: -W: invalid argument\n", argv[0]);
                return 1;
            }
            break;
        }
        case 'H': {
            char *end;
            user_height = strtol(optarg, &end, 10);
            if (*end) {
                fprintf(stderr, "%s: -H: invalid argument\n", argv[0]);
                return 1;
            }
            break;
        }
        default: return -2;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "usage: %s [OPTION]... EXECUTABLE [CMDLINE]\n", progname);
        return 1;
    }

    kernel_path = argv[optind++];
    kernel_image = mmap_file(kernel_path, &kernel_size);
    if (optind < argc) cmdline = argv[optind++];

    if (!libboot_mem_init(LIBBOOT_MEM_CLONE_RAW_MMAP | LIBBOOT_MEM_MAINTAIN_MMAP)) {
        fprintf(stderr, "%s: failed to initialize memory: %m\n", progname);
        return 1;
    }

    init_cpufeat();
    init_image();

    init_requests();
    paddr_t stack_addr;
    void *stack_ptr;
    size_t stack_size;

    {
        stack_size = 0x10000;
        struct limine_stack_size_request *request = get_request(REQUEST_STACK_SIZE);
        if (request && request->stack_size > stack_size) stack_size = request->stack_size;

        stack_addr = UINT32_MAX; // the prekernel uses this
        stack_ptr = alloc_pages(&stack_addr, stack_size, 16, LIMINE_MEMORY_LOADER);
        boot_info_phys = stack_addr;
        stack_addr += stack_size;
    }

    init_paging();
    uint32_t prekernel = load_prekernel();
    init_hhdm();
    fill_response_pointers();

    {
        struct limine_entry_point_request *request = get_request(REQUEST_ENTRY_POINT);
        if (request) boot_info.entry_point = request->entry;
    }

    // These must be done BEFORE load_image(), because they might modify the image in memory.
    init_rsdp();
    init_module();

    load_image();

    // This must be done AFTER load_image()
    {
        struct limine_mp_request *request = get_request(REQUEST_SMP);
        if (request && boot_info.responses.rsdp.address) {
            boot_info.mp_response_field_ptr = paging_resolve(
                    offset_to_virt((void *)request - kernel_image) + offsetof(struct limine_mp_request, response)
            );

            paddr_t addr = 0xfffff;
            alloc_pages(&addr, 0x1000, 0x1000, LIMINE_MEMORY_LOADER);
            boot_info.mp_low_page = addr;
            boot_info.mp_flags = request->flags;
            boot_info.mp_stack_pages = (stack_size + 0xfff) >> 12;
        }
    }

    // While not a hard requirement, this should be one of the last things done before handover,
    // since saving and restoring the video mode in case of errors looks ugly to the user
    init_framebuffer();

    // Perform handover
    create_hhdm(); // This must be the LAST operation done before creating the memory map.
    init_memmap(); // This must be the LAST operation done before copying the boot information.
    // From now on, we must not allocate physical memory.
    memcpy(stack_ptr, &boot_info, sizeof(boot_info));
    paging_finalize();
    andromeda_cpu_regs_t regs = {
            .eax = kernel_efer_value,
            .ebx = kernel_cr4_value,
            .ecx = top_page_table_phys,
            .edx = kernel_efer_value >> 32,
            .esi = boot_info_phys,
            .cs = 0x18,
            .ds = 0x20,
            .es = 0x20,
            .fs = 0x20,
            .gs = 0x20,
            .ss = 0x20,
            .esp = stack_addr,
            .eip = prekernel,
            .gdtr.limit = sizeof(boot_info.gdt) - 1,
            .gdtr.base = boot_info_phys + offsetof(boot_info_t, gdt),
    };
    libboot_handover(&regs);
    fprintf(stderr, "%s: failed to start kernel: %m\n", progname);
    return 1;
}
