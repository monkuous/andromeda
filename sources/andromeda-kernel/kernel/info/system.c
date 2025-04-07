#include "system.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "info/acpi.h"
#include "mem/bootmem.h"
#include "mem/vmalloc.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

static file_t *open_file(const char *name) {
    unsigned char buffer[32];
    size_t length = snprintk(buffer, sizeof(buffer), "/sys/%s", name);
    ASSERT(length <= sizeof(buffer));

    file_t *file;
    int error = vfs_open(&file, nullptr, buffer, length, O_CREAT | O_EXCL | O_TRUNC | O_RDWR, 0600);
    if (unlikely(error)) panic("failed to create %S (%d)", buffer, length, error);

    return file;
}

static void print(file_t *file, const char *format, ...) {
    va_list args;
    va_start(args, format);
    int error = vfprintk(file, format, args);
    va_end(args);
    if (unlikely(error)) panic("failed to write to sysfs file (%d)", error);
}

static bool populate_mmap_cb(uint64_t head, uint64_t tail, memory_type_t type, void *file) {
    const char *type_string;

    switch (type) {
    case MEM_USABLE: type_string = "usable"; break;
    case MEM_ACPI_RECLAIM: type_string = "acpi-reclaimable"; break;
    case MEM_ACPI_NVS: type_string = "acpi-nvs"; break;
    case MEM_RESERVED: type_string = "reserved"; break;
    }

    print(file, "0x%16X-0x%16X %s\n", head, tail, type_string);
    return true;
}

static void populate_mmap() {
    file_t *file = open_file("memory-map");
    bootmem_iter(populate_mmap_cb, file, false);
    file_deref(file);
}

static void populate_acpi() {
    uint64_t phys;
    size_t length;
    void *rsdp = acpi_find_rsdp(&phys, &length);
    if (!rsdp) return;

    file_t *file = open_file("acpi-rsdp-addr");
    print(file, "0x%X\n", phys);
    file_deref(file);

    file = open_file("acpi-rsdp");
    write_or_die(file, rsdp, length);
    file_deref(file);

    vmfree(rsdp, length);
}

void populate_sysfs() {
    printk("kernel: populating /sys\n");
    populate_mmap();
    populate_acpi();
}
