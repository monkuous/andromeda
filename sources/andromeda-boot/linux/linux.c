#include "linux.h"
#include "libboot.h"
#include "utils.h"
#include <andromeda/cpu.h>
#include <andromeda/memory.h>
#include <andromeda/video.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#define PROTOCOL_MIN PROTOCOL_2_05

const char *progname;
static ssize_t user_width = -1;
static ssize_t user_height = -1;

typedef struct {
    uint64_t gdt[4];
    char cmdline[];
} start_data_t;

typedef struct {
    const char *path;
    const void *ptr;
    size_t size;
} initrd_t;

static initrd_t *initrds;
static size_t num_initrd;
static size_t tot_initrd_size;

static void fill_setup_info(const linux_image_t *, setup_info_t *info, paddr_t kernel_phys, paddr_t start_data_phys) {
    paddr_t initrd_phys;

    if (tot_initrd_size) {
        initrd_phys = UINT32_MAX;
        void *virt = alloc_pages(&initrd_phys, tot_initrd_size, 1, 0);

        for (size_t i = 0; i < num_initrd; i++) {
            printf("loading initrd %s\n", initrds[i].path);
            memcpy(virt, initrds[i].ptr, initrds[i].size);
            virt += initrds[i].size;
        }
    } else {
        initrd_phys = 0;
    }

    info->vid_mode = 0xffff;
    info->type_of_loader = 0xff;
    info->loadflags &= ~(LINUX_LOADFLAGS_CAN_USE_HEAP | LINUX_LOADFLAGS_KEEP_SEGMENTS | LINUX_LOADFLAGS_QUIET);
    info->code32_start = kernel_phys;
    info->ramdisk_image = initrd_phys;
    info->ramdisk_size = tot_initrd_size;
    info->cmd_line_ptr = start_data_phys + offsetof(start_data_t, cmdline);
    info->setup_data = 0;
}

static void fill_e820(boot_params_t *params) {
    size_t size;
    const libboot_mem_region_t *mmap = libboot_mem_get_raw_map(&size);

    size_t i;

    for (i = 0; i < size && i < sizeof(params->e820_table) / sizeof(*params->e820_table); i++) {
        params->e820_table[i].addr = mmap[i].head;
        params->e820_table[i].size = mmap[i].tail - mmap[i].head + 1;

        switch (mmap[i].type) {
        case LIBBOOT_MEMORY_USABLE: params->e820_table[i].type = 1; break;
        case LIBBOOT_MEMORY_ACPI_RECLAIMABLE: params->e820_table[i].type = 3; break;
        case LIBBOOT_MEMORY_ACPI_NVS: params->e820_table[i].type = 4; break;
        default: params->e820_table[i].type = 2; break; // unrecognized type, assume reserevd
        }
    }

    params->e820_entries = i;
}

static void fill_acpi(boot_params_t *params) {
    paddr_t addr;
    if (libboot_acpi_get_rsdp_addr(&addr)) {
        params->acpi_rsdp_addr = addr;
    }
}

static void fill_video_fb(screen_info_t *info, andromeda_framebuffer_t *fb) {
    info->flags = VIDEO_FLAGS_NO_CURSOR;

    switch (fb->mode.memory_model) {
    case ANDROMEDA_MEMORY_MODEL_CGA_TEXT:
        info->orig_video_isVGA = VIDEO_TYPE_VGAC;
        info->orig_video_mode = 3;
        info->orig_video_ega_bx = 3;
        info->orig_video_cols = fb->mode.width;
        info->orig_video_lines = fb->mode.height;
        info->orig_video_points = 16;
        break;
    case ANDROMEDA_MEMORY_MODEL_RGB:
        info->orig_video_isVGA = VIDEO_TYPE_VLFB;
        info->capabilities = VIDEO_CAPABILITY_64BIT_BASE | VIDEO_CAPABILITY_SKIP_QUIRKS;
        info->lfb_base = fb->address;
        info->ext_lfb_base = fb->address >> 32;
        info->lfb_size = fb->mode.pitch * fb->mode.height;
        info->lfb_linelength = fb->mode.pitch;
        info->lfb_width = fb->mode.width;
        info->lfb_height = fb->mode.height;
        info->lfb_depth = fb->mode.bits_per_pixel;
        info->red_size = fb->mode.rgb.red.mask_size;
        info->red_pos = fb->mode.rgb.red.field_pos;
        info->green_size = fb->mode.rgb.green.mask_size;
        info->green_pos = fb->mode.rgb.green.field_pos;
        info->blue_size = fb->mode.rgb.blue.mask_size;
        info->blue_pos = fb->mode.rgb.blue.field_pos;
        break;
    }
}

static void fill_video_consolefb(screen_info_t *info) {
    andromeda_framebuffer_t fb;

    if (libboot_video_get_console_fb(&fb)) {
        fill_video_fb(info, &fb);
    }
}

static bool fill_video_pick(boot_params_t *params) {
    size_t cards = libboot_video_num_cards();

    for (size_t i = 0; i < cards; i++) {
        libboot_video_card_t *card = libboot_video_get_card(i);
        ssize_t nmodes = libboot_video_discover_modes(card);
        if (nmodes < 0) {
            fprintf(stderr, "%s: failed to get video mode list: %m\n", progname);
            exit(1);
        }
        if (nmodes == 0) continue;

        ssize_t mode = libboot_video_pick_mode(card, user_width, user_height);
        if (mode < 0) {
            if (errno == ENODATA) continue;
            fprintf(stderr, "%s: failed to pick video mode: %m\n", progname);
            exit(1);
        }

        andromeda_framebuffer_t fb;
        int fd = libboot_video_set_mode(card, &fb, mode);
        if (fd < 0) {
            fprintf(stderr, "%s: failed to set video mode: %m\n", progname);
            exit(1);
        }

        fill_video_fb(&params->screen_info, &fb);

        size_t edid_size;
        const void *edid = libboot_video_get_edid_data(card, &edid_size);
        if (edid) {
            memcpy(&params->edid_info, edid, sizeof(params->edid_info));
        }

        return true;
    }

    return false;
}

static void fill_video(boot_params_t *info) {
    if (!fill_video_pick(info)) fill_video_consolefb(&info->screen_info);
}

static void fill_boot_params(
        const linux_image_t *image,
        boot_params_t *params,
        paddr_t kernel_phys,
        paddr_t start_data_phys
) {
    uint32_t setup_end = 0x202 + image->info.jump[1];

    memset(params, 0, sizeof(*params));
    memcpy(&params->setup_info, &image->info, setup_end - offsetof(linux_image_t, info));

    fill_setup_info(image, &params->setup_info, kernel_phys, start_data_phys);
    fill_e820(params);
    fill_acpi(params);
    fill_video(params);
}

static void load_kernel(const linux_image_t *image, uint32_t start_data_phys) {
    unsigned protocol = image->info.version;
    printf("protocol: %u.%.2u\n", protocol >> 8, protocol & 0xff);

    uint32_t kernel_start = image->info.setup_sects;
    if (!kernel_start) kernel_start = 4;
    kernel_start += 1;
    kernel_start *= 512;

    printf("kernel_start: 0x%x\n", kernel_start);
    printf("alignment: 0x%x\n", image->info.kernel_alignment);
    printf("syssize: 0x%x\n", image->info.syssize << 4);
    printf("init_size: 0x%x\n", image->info.init_size);

    paddr_t kernel_phys = UINT32_MAX, params_phys = UINT32_MAX;
    void *kernel = alloc_pages(&kernel_phys, image->info.init_size, image->info.kernel_alignment, 0);
    void *params = alloc_pages(&params_phys, sizeof(boot_params_t), 0x1000, 0);

    printf("allocated memory for kernel at 0x%llx (mapped to %p)\n", kernel_phys, kernel);
    printf("zero page at 0x%llx (%p)\n", params_phys, params);

    fill_boot_params(image, params, kernel_phys, start_data_phys);

    printf("loading kernel image\n");
    memcpy(kernel, (const void *)image + kernel_start, image->info.syssize << 4);
    printf("starting kernel\n");

    andromeda_cpu_regs_t regs = {
            .esi = params_phys,
            .ds = 0x18,
            .es = 0x18,
            .fs = 0x18,
            .gs = 0x18,
            .ss = 0x18,
            .cs = 0x10,
            .eip = kernel_phys,
            .gdtr =
                    {
                            .limit = sizeof(((start_data_t){}).gdt) - 1,
                            .base = start_data_phys + offsetof(start_data_t, gdt),
                    },
    };

    libboot_handover(&regs);
    fprintf(stderr, "%s: failed to start kernel: %m\n", progname);
    exit(1);
}

static void add_initrd(const char *path) {
    size_t idx = num_initrd++;
    initrds = realloc(initrds, num_initrd * sizeof(*initrds));
    initrds[idx].path = path;
    initrds[idx].ptr = mmap_file(path, &initrds[idx].size);
    tot_initrd_size += initrds[idx].size;
}

int main(int argc, char *argv[]) {
    progname = argv[0];

    int c;
    while ((c = getopt(argc, argv, "hi:W:H:")) != -1) {
        switch (c) {
        case '?': return 2;
        case 'h':
            printf("usage: %s [OPTION...] KERNEL [CMDLINE]\n"
                   "\n"
                   "options:\n"
                   "  -h        show this help message\n"
                   "  -i FILE   load FILE as initrd (can be specified multiple times)\n"
                   "  -W NUM    try to pick a video mode with a width of NUM pixels\n"
                   "  -H NUM    try to pick a video mode with a height of NUM pixels\n",
                   argv[0]);
            return 0;
        case 'i': add_initrd(optarg); break;
        case 'W': {
            char *end;
            user_width = strtol(optarg, &end, 10);
            if (*end) {
                fprintf(stderr, "%s: -w: invalid argument\n", argv[0]);
                return 1;
            }
            break;
        }
        case 'H': {
            char *end;
            user_height = strtol(optarg, &end, 10);
            if (*end) {
                fprintf(stderr, "%s: -w: invalid argument\n", argv[0]);
                return 1;
            }
            break;
        }
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "usage: %s [OPTION...] KERNEL [CMDLINE]\n", argv[0]);
        return 2;
    }

    const char *kernel_path = argv[optind++];
    const char *cmdline = optind < argc ? argv[optind++] : "";

    const linux_image_t *image = mmap_file(kernel_path, nullptr);

    const setup_info_t *info = &image->info;
    if (info->header != LINUX_MAGIC || info->version < PROTOCOL_MIN) {
        fprintf(stderr, "%s: %s does not appear to be a linux kernel\n", argv[0], argv[1]);
        return 1;
    }

    if (!info->relocatable_kernel) {
        fprintf(stderr, "%s: %s is not a relocatable kernel\n", argv[0], argv[1]);
        return 1;
    }

    if (info->kernel_alignment & (info->kernel_alignment - 1)) {
        fprintf(stderr, "%s: %s: kernel alignment is not a power of two\n", argv[0], argv[1]);
        return 1;
    }

    if (!libboot_mem_init(0)) {
        fprintf(stderr, "%s: failed to initialize memory: %m\n", argv[0]);
        return 1;
    }

    if (!libboot_video_init(0)) {
        fprintf(stderr, "%s: failed to initialize video: %m\n", argv[0]);
        return 1;
    }

    uint64_t start_data_phys = UINT32_MAX;
    start_data_t *start_data = alloc_pages(
            &start_data_phys,
            offsetof(start_data_t, cmdline) + strlen(cmdline) + 1,
            alignof(start_data_t),
            0
    );
    start_data->gdt[2] = 0xcf9b000000ffff;
    start_data->gdt[3] = 0xcf93000000ffff;
    strcpy(start_data->cmdline, cmdline);

    load_kernel(image, start_data_phys);
}
