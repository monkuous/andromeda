#include "linux.h"
#include <andromeda/cpu.h>
#include <andromeda/memory.h>
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

#define PROTOCOL_MIN PROTOCOL_2_05

static int mem_fd;
static char *progname;

typedef struct {
    uint64_t gdt[4];
    char cmdline[];
} start_data_t;

static FILE *do_open(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "%s: failed to open %s: %m\n", progname, path);
        exit(1);
    }
    return file;
}

static FILE *maybe_open(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file && errno != ENOENT) {
        fprintf(stderr, "%s: failed to open %s: %m\n", progname, path);
        exit(1);
    }
    return file;
}

static uint32_t phys_alloc(void **virt_out, size_t pages, size_t align) {
    andromeda_pmalloc_t request = {
            .pages = pages,
            .align = align,
            .addr = UINT32_MAX,
    };

    int fd = ioctl(mem_fd, IOCTL_PMALLOC, &request);
    if (fd < 0) {
        fprintf(stderr, "%s: failed to allocate physical memory: %m\n", progname);
        exit(1);
    }

    void *base = mmap(NULL, request.pages << 12, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (base == MAP_FAILED) {
        fprintf(stderr, "%s: failed to map allocated memory: %m\n", progname);
        exit(1);
    }
    *virt_out = base;

    close(fd);
    return request.addr;
}

static void fill_setup_info(
        const linux_image_t *,
        setup_info_t *info,
        uint32_t kernel_phys,
        uint32_t start_data_phys,
        const void *initrd,
        size_t initrd_size
) {
    uint32_t initrd_phys;

    if (initrd_size) {
        void *virt;
        initrd_phys = phys_alloc(&virt, (initrd_size + 0xfff) >> 12, 0x1000);
        printf("loading initrd\n");
        memcpy(virt, initrd, initrd_size);
    } else {
        initrd_phys = 0;
    }

    info->vid_mode = 0xffff;
    info->type_of_loader = 0xff;
    info->loadflags &= ~(LINUX_LOADFLAGS_CAN_USE_HEAP | LINUX_LOADFLAGS_KEEP_SEGMENTS | LINUX_LOADFLAGS_QUIET);
    info->code32_start = kernel_phys;
    info->ramdisk_image = initrd_phys;
    info->ramdisk_size = initrd_size;
    info->cmd_line_ptr = start_data_phys + offsetof(start_data_t, cmdline);
    info->setup_data = 0;
}

static void fill_e820(boot_params_t *params) {
    FILE *file = do_open("/sys/memory-map");

    while (params->e820_entries < sizeof(params->e820_table) / sizeof(*params->e820_table)) {
        uint64_t head, tail;
        char type[32];
        if (fscanf(file, "%llx-%llx %s", &head, &tail, type) < 3) break;

        if (head < 0x1000) head = 0x1000;
        if (head > tail) continue;

        boot_e820_entry_t *entry = &params->e820_table[params->e820_entries++];

        entry->addr = head;
        entry->size = tail - head + 1;

        if (!strcmp(type, "usable")) entry->type = 1;
        else if (!strcmp(type, "acpi-reclaimable")) entry->type = 3;
        else if (!strcmp(type, "acpi-nvs")) entry->type = 4;
        else entry->type = 2; // assume all unrecognized types are reserved

        printf("got e820: %#llx-%#llx %u\n", entry->addr, entry->addr + entry->size, entry->type);
    }

    fclose(file);
}

static void fill_acpi(boot_params_t *params) {
    FILE *file = maybe_open("/sys/acpi-rsdp-addr");
    if (!file) return;

    uint64_t addr;
    if (fscanf(file, "%llx", &addr)) {
        params->acpi_rsdp_addr = addr;
        printf("got rsdp: %#llx\n", addr);
    }

    fclose(file);
}

static void fill_boot_params(
        const linux_image_t *image,
        boot_params_t *params,
        uint32_t kernel_phys,
        uint32_t start_data_phys,
        const void *initrd,
        size_t initrd_size
) {
    uint32_t setup_end = 0x202 + image->info.jump[1];

    memset(params, 0, sizeof(*params));
    memcpy(&params->setup_info, &image->info, setup_end - offsetof(linux_image_t, info));

    fill_setup_info(image, &params->setup_info, kernel_phys, start_data_phys, initrd, initrd_size);
    fill_e820(params);
    fill_acpi(params);

    // todo: determine these values properly
    params->screen_info.orig_video_mode = 3;
    params->screen_info.orig_video_ega_bx = 3;
    params->screen_info.orig_video_lines = 25;
    params->screen_info.orig_video_cols = 80;
    params->screen_info.orig_video_points = 16;
    params->screen_info.orig_video_isVGA = 0x22;
}

static void load_kernel(const linux_image_t *image, uint32_t start_data_phys, const void *initrd, size_t initrd_size) {
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

    void *kernel;
    uint32_t kernel_phys = phys_alloc(&kernel, (image->info.init_size + 0xfff) >> 12, image->info.kernel_alignment);

    void *params;
    uint32_t params_phys = phys_alloc(&params, 1, 0x1000);

    printf("allocated memory for kernel at 0x%x (mapped to %p)\n", kernel_phys, kernel);
    printf("zero page at 0x%x (%p)\n", params_phys, params);

    fill_boot_params(image, params, kernel_phys, start_data_phys, initrd, initrd_size);

    printf("loading kernel image\n");
    memcpy(kernel, (const void *)image + kernel_start, image->info.syssize << 4);
    printf("starting kernel\n");

    int cpu_fd = open("/dev/cpu", O_WRONLY);
    if (cpu_fd < 0) {
        fprintf(stderr, "%s: failed to open /dev/cpu: %m\n", progname);
        exit(1);
    }

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

    ioctl(cpu_fd, IOCTL_SET_REGISTERS, &regs);
    fprintf(stderr, "%s: failed to start kernel: %m\n", progname);
    exit(1);
}

static const void *mmap_file(const char *path, size_t *size_out) {
    if (!path) {
        if (size_out) *size_out = 0;
        return nullptr;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s: open failed: %m\n", progname, path);
        exit(1);
    }

    struct stat stat;
    if (fstat(fd, &stat)) {
        fprintf(stderr, "%s: %s: stat failed: %m\n", progname, path);
        exit(1);
    }

    void *ptr = mmap(nullptr, (stat.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "%s: %s: mmap failed: %m\n", progname, path);
        exit(1);
    }

    if (size_out) *size_out = stat.st_size;
    return ptr;
}

int main(int argc, char *argv[]) {
    progname = argv[0];

    const char *initrd_path = nullptr;
    int c;

    while ((c = getopt(argc, argv, "+i:")) != -1) {
        if (c == '?' || c == ':') return 2;
        initrd_path = optarg;
    }

    if (optind >= argc) {
        fprintf(stderr, "usage: %s [-i INITRD] KERNEL [CMDLINE]\n", argv[0]);
        return 2;
    }

    const char *kernel_path = argv[optind++];
    const char *cmdline = optind < argc ? argv[optind++] : "";

    size_t initrd_size;
    const linux_image_t *image = mmap_file(kernel_path, nullptr);
    const void *initrd = mmap_file(initrd_path, &initrd_size);

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

    mem_fd = open("/dev/mem", O_RDWR);
    if (mem_fd < 0) {
        fprintf(stderr, "%s: failed to open /dev/mem: %m", argv[0]);
        return 1;
    }

    void *virt;
    uint32_t start_data_phys = phys_alloc(
            &virt,
            (offsetof(start_data_t, cmdline) + strlen(cmdline) + 0x1000) >> 12,
            0x1000
    );
    start_data_t *start_data = virt;
    start_data->gdt[2] = 0xcf9b000000ffff;
    start_data->gdt[3] = 0xcf93000000ffff;
    strcpy(start_data->cmdline, cmdline);

    load_kernel(image, start_data_phys, initrd, initrd_size);
}
