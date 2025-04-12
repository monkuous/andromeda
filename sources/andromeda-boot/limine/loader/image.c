#include "image.h"
#include "image-elf.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "memory.h"
#include "pathutil.h"
#include "requests.h"
#include "utils.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static enum {
    FORMAT_ELF,
} format;

static void determine_format() {
    if (kernel_size >= 4 && !memcmp(kernel_image, "\177ELF", 4)) {
        format = FORMAT_ELF;
    } else {
        fprintf(stderr, "%s: unknown executable format\n", progname);
        exit(1);
    }
}

void init_image() {
    determine_format();

    switch (format) {
    case FORMAT_ELF: init_elf(); break;
    }
}

void load_image() {
    struct limine_executable_cmdline_request *cmdline_req = get_request(REQUEST_EXECUTABLE_CMDLINE);
    struct limine_executable_file_request *file_req = get_request(REQUEST_EXECUTABLE_FILE);

    if (file_req) {
        uint64_t hhdm = boot_info.responses.hhdm.offset;

        char *path = get_volume_path(kernel_path);
        size_t data_offs = (kernel_size + 7) & ~7;
        size_t path_size = strlen(path) + 1;
        size_t string_size = (cmdline ? strlen(cmdline) : 0) + 1;
        size_t total_size = data_offs + sizeof(struct limine_file) + path_size + string_size;

        paddr_t phys = UINT64_MAX;
        void *virt = alloc_pages(&phys, total_size, 0x1000, LIMINE_MEMORY_LOADER);
        memcpy(virt, kernel_image, kernel_size);
        memcpy(virt + data_offs + sizeof(struct limine_file), path, path_size);
        memcpy(virt + data_offs + sizeof(struct limine_file) + path_size, cmdline ? cmdline : "", string_size);

        struct limine_file *file = virt + data_offs;
        memset(file, 0, sizeof(*file));
        file->address = hhdm + phys;
        file->size = kernel_size;
        file->path = hhdm + phys + data_offs + sizeof(*file);
        file->string = hhdm + phys + data_offs + sizeof(*file) + path_size;
        file->media_type = LIMINE_MEDIA_TYPE_GENERIC;

        boot_info.responses.executable_file.executable_file = hhdm + phys + data_offs;
        boot_info.responses.executable_cmdline.cmdline = file->string;
    } else if (cmdline_req) {
        if (cmdline) {
            size_t size = strlen(cmdline) + 1;
            paddr_t phys = UINT64_MAX;
            void *virt = alloc_pages(&phys, size, 1, LIMINE_MEMORY_LOADER);
            memcpy(virt, cmdline, size);
            boot_info.responses.executable_cmdline.cmdline = boot_info.responses.hhdm.offset + phys;
        } else {
            cmdline_req->response = 0;
        }
    }

    switch (format) {
    case FORMAT_ELF: load_elf(); break;
    }
}

uint64_t offset_to_virt(uint64_t offset) {
    switch (format) {
    case FORMAT_ELF: return elf_offset_to_virt(offset);
    default: unreachable();
    }
}
