#include "acpi.h"
#include "memory.h"
#include "start.h"
#include <stdint.h>

typedef struct {
    uint64_t addr;
    size_t size;
} table_data_t;

typedef struct {
    uint8_t signature[8];
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t revision;
    uint32_t rsdt_address;
    uint32_t length;
    uint64_t xsdt_address;
    uint8_t ext_checksum;
    uint8_t reserved[3];
} rsdp_t;

// multi-byte char constants: 'ABCD' == 0x41424344
// we're little endian, so to get the right values we need to reverse the
// signature text
static const uint32_t table_signatures[TABLE_MAX] = {
        [TABLE_MADT] = 'CIPA',
};
static table_data_t tables[TABLE_MAX];

void init_acpi() {
    rsdp_t rsdp;
    copy_from_phys(&rsdp, boot_info->responses.rsdp.address, offsetof(rsdp_t, length), true);
    bool root_xsdt = rsdp.revision >= 2;

    if (root_xsdt) {
        rsdp_t rsdp;
        copy_from_phys(&rsdp, boot_info->responses.rsdp.address, offsetof(rsdp_t, ext_checksum), true);
    }

    table_header_t root_header;
    uint64_t root_addr = root_xsdt ? rsdp.xsdt_address : rsdp.rsdt_address;
    copy_from_phys(&root_header, root_addr, sizeof(root_header), true);
    size_t entry_size = root_xsdt ? 8 : 4;

    for (size_t i = sizeof(root_header); i < root_header.length; i += entry_size) {
        uint64_t entry = 0;
        copy_from_phys(&entry, root_addr + i, entry_size, true);

        table_header_t header;
        copy_from_phys(&header, entry, sizeof(header), true);

        for (int i = 0; i < TABLE_MAX; i++) {
            if (header.signature == table_signatures[i]) {
                tables[i].addr = entry;
                tables[i].size = header.length;
            }
        }
    }
}

size_t get_table(table_t table, uint64_t *addr_out) {
    *addr_out = tables[table].addr;
    return tables[table].size;
}
