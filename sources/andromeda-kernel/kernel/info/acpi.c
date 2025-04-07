#include "acpi.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/print.h"
#include <stdint.h>

typedef struct [[gnu::packed]] {
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t ext_checksum;
} rsdp_t;

#define OLD_LENGTH offsetof(rsdp_t, length)

static bool verify_checksum(const void *ptr, size_t size) {
    unsigned char sum = 0;

    while (size--) sum += *(const unsigned char *)ptr++;

    return sum == 0;
}

static void *try_area(uint64_t *phys_out, size_t *len_out, uint32_t base, size_t size) {
    if (size < OLD_LENGTH) return nullptr;
    size -= OLD_LENGTH; // make size the highest allowed offset

    rsdp_t buf;

    for (size_t i = 0; i <= size; i += 16) {
        uint32_t phys = base + i;
        copy_from_phys(&buf, phys, OLD_LENGTH);

        if (memcmp(buf.signature, "RSD PTR ", 8)) continue;

        if (!verify_checksum(&buf, OLD_LENGTH)) {
            printk("acpi: rsdp candidate at 0x%x has invalid checksum\n", phys);
            continue;
        }

        if (buf.revision >= 2) {
            size_t wanted = offsetof(rsdp_t, length) + sizeof(buf.length);
            size_t extra_avail = size - i;

            if (extra_avail < wanted - OLD_LENGTH) {
            too_large:
                printk("acpi: rsdp candidate at 0x%x goes beyond the search area\n", phys);
                continue;
            }

            copy_from_phys(&buf, base + i, wanted);
            if (extra_avail < buf.length - OLD_LENGTH) goto too_large;

            void *area = vmalloc(buf.length);
            copy_from_phys(area, base + i, buf.length);

            if (!verify_checksum(area, buf.length)) {
                vmfree(area, buf.length);
                printk("acpi: rsdp candidate at 0x%x has invalid extended checksum\n", phys);
                continue;
            }

            *phys_out = phys;
            *len_out = buf.length;
            return area;
        }

        void *area = vmalloc(OLD_LENGTH);
        memcpy(area, &buf, OLD_LENGTH);
        *phys_out = phys;
        *len_out = OLD_LENGTH;
        return area;
    }

    return nullptr;
}

void *acpi_find_rsdp(uint64_t *phys_out, size_t *length_out) {
    uint16_t ebda_seg;
    copy_from_phys(&ebda_seg, 0x40e, sizeof(ebda_seg));

    void *ptr = try_area(phys_out, length_out, (uint32_t)ebda_seg << 4, 1024);
    if (!ptr) ptr = try_area(phys_out, length_out, 0xe0000, 0x20000);
    return ptr;
}
