#include "module.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "memory.h"
#include "pathutil.h"
#include "utils.h"
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct module {
    struct module *next;
    const void *data;
    size_t size;
    const char *string;
    size_t string_size;
    const char *path;
    size_t path_size;
};

static module_t *first, *last;

module_t *add_module(const char *path) {
    module_t *module = malloc(sizeof(*module));
    module->next = nullptr;
    module->data = mmap_file(path, &module->size);
    module->string = "";
    module->path = get_volume_path(path);
    module->path_size = strlen(module->path) + 1;

    if (last) last->next = module;
    else first = module;
    last = module;

    return module;
}

void set_module_string(module_t *module, const char *string) {
    module->string = string;
}

void init_module() {
    size_t num_modules = 0;
    size_t strings_size = 0;

    for (module_t *cur = first; cur; cur = cur->next) {
        cur->string_size = strlen(cur->string) + 1;
        num_modules += 1;
        strings_size += cur->string_size;
        strings_size += cur->path_size;
    }

    if (!num_modules) return;

    size_t ptrs_size = num_modules * sizeof(uint64_t);
    size_t data_size = num_modules * sizeof(struct limine_file);
    size_t total_size = ptrs_size + data_size + strings_size;

    paddr_t phys = UINT64_MAX;
    void *virt = alloc_pages(&phys, total_size, 8, LIMINE_MEMORY_LOADER);

    uint64_t *pointers = virt;
    struct limine_file *data = virt + ptrs_size;
    void *strings = virt + ptrs_size + data_size;

    memset(data, 0, data_size);

    for (module_t *cur = first; cur; cur = cur->next, pointers++, data++) {
        *pointers = boot_info.responses.hhdm.offset + phys + ((void *)data - virt);

        {
            paddr_t address = UINT64_MAX;
            void *virt = alloc_pages(&address, cur->size, 0x1000, LIMINE_MEMORY_KERNEL);
            printf("loading %s\n", cur->path);
            memcpy(virt, cur->data, cur->size);
            data->address = address + boot_info.responses.hhdm.offset;
        }

        data->size = cur->size;
        data->path = boot_info.responses.hhdm.offset + phys + ((void *)strings - virt);
        memcpy(strings, cur->path, cur->path_size);
        strings += cur->path_size;
        data->string = boot_info.responses.hhdm.offset + phys + ((void *)strings - virt);
        memcpy(strings, cur->string, cur->string_size);
        strings += cur->string_size;
        data->media_type = LIMINE_MEDIA_TYPE_GENERIC;
    }

    boot_info.responses.module.module_count = num_modules;
    boot_info.responses.module.modules = boot_info.responses.hhdm.offset + phys;
}
