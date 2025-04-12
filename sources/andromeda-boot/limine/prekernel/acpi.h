#pragma once

#include <stddef.h>
#include <stdint.h>

typedef enum {
    TABLE_MADT,
    TABLE_MAX,
} table_t;

typedef struct {
    uint32_t signature;
    uint32_t length;
    uint8_t revision;
    uint8_t checksum;
    uint8_t oem_id[6];
    uint8_t oem_table_id[8];
    uint32_t oem_revision;
    uint32_t creator_id;
    uint32_t creator_revision;
} table_header_t;

typedef struct {
    table_header_t header;
    uint32_t address;
    uint32_t flags;
} madt_t;

#define MADT_PCAT_COMPAT 1

typedef struct {
    uint8_t type;
    uint8_t length;
    union {
        struct [[gnu::packed]] {
            uint8_t acpi_id;
            uint8_t apic_id;
            uint32_t flags;
        } xapic;
        struct [[gnu::packed]] {
            uint8_t id;
            uint8_t reserved;
            uint32_t address;
            uint32_t gsi_base;
        } ioapic;
        struct [[gnu::packed]] {
            uint16_t reserved;
            uint32_t apic_id;
            uint32_t flags;
            uint32_t acpi_id;
        } x2apic;
    };
} madt_entry_t;

#define MADT_XAPIC 0
#define MADT_IOAPIC 1
#define MADT_X2APIC 9

#define MADT_LAPIC_ENABLED 1
#define MADT_LAPIC_ONLINE_CAPABLE 2

void init_acpi();
size_t get_table(table_t table, uint64_t *addr_out);
