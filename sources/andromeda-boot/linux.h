#pragma once

#include <stdint.h>

typedef struct [[gnu::packed]] {
    uint8_t setup_sects;
    uint16_t root_flags;
    uint32_t syssize;
    uint16_t ram_size;
    uint16_t vid_mode;
    uint16_t boot_dev;
    uint16_t boot_flag;
    uint8_t jump[2];
    uint32_t header;
    uint16_t version;
    uint32_t realmode_swtch;
    uint16_t start_sys_seg;
    uint16_t kernel_version;
    uint8_t type_of_loader;
    uint8_t loadflags;
    uint16_t setup_move_size;
    uint32_t code32_start;
    uint32_t ramdisk_image;
    uint32_t ramdisk_size;
    uint32_t bootsect_kludge;
    uint16_t heap_end_ptr;
    uint8_t ext_loader_ver;
    uint8_t ext_loader_type;
    uint32_t cmd_line_ptr;
    uint32_t initrd_addr_max;
    uint32_t kernel_alignment;
    uint8_t relocatable_kernel;
    uint8_t min_alignment;
    uint16_t xloadflags;
    uint32_t cmdline_size;
    uint32_t hardware_subarch;
    uint64_t hardware_subarch_data;
    uint32_t payload_offset;
    uint32_t payload_length;
    uint64_t setup_data;
    uint64_t pref_address;
    uint32_t init_size;
    uint32_t handover_offset;
    uint32_t kernel_info_offset;
} setup_info_t;

typedef struct [[gnu::packed, gnu::aligned(0x1000)]] {
    uint8_t padding[0x1f1];
    setup_info_t info;
} linux_image_t;

typedef struct [[gnu::packed]] {
    uint8_t orig_x;
    uint8_t orig_y;
    uint16_t ext_mem_k;
    uint16_t orig_video_page;
    uint8_t orig_video_mode;
    uint8_t orig_video_cols;
    uint8_t flags;
    uint8_t unused2;
    uint16_t orig_video_ega_bx;
    uint16_t unused3;
    uint8_t orig_video_lines;
    uint8_t orig_video_isVGA;
    uint16_t orig_video_points;
    uint16_t lfb_width;
    uint16_t lfb_height;
    uint16_t lfb_depth;
    uint32_t lfb_base;
    uint32_t lfb_size;
    uint16_t cl_magic, cl_offset;
    uint16_t lfb_linelength;
    uint8_t red_size;
    uint8_t red_pos;
    uint8_t green_size;
    uint8_t green_pos;
    uint8_t blue_size;
    uint8_t blue_pos;
    uint8_t rsvd_size;
    uint8_t rsvd_pos;
    uint16_t vesapm_seg;
    uint16_t vesapm_off;
    uint16_t pages;
    uint16_t vesa_attributes;
    uint32_t capabilities;
    uint32_t ext_lfb_base;
    uint8_t reserved[2];
} screen_info_t;

typedef struct [[gnu::packed]] {
    uint16_t version;
    uint16_t cseg;
    uint32_t offset;
    uint16_t cseg_16;
    uint16_t dseg;
    uint16_t flags;
    uint16_t cseg_len;
    uint16_t cseg_16_len;
    uint16_t dseg_len;
} apm_bios_info_t;

typedef struct [[gnu::packed]] {
    uint32_t signature;
    uint32_t command;
    uint32_t event;
    uint32_t perf_level;
} ist_info_t;

typedef struct [[gnu::packed]] {
    uint16_t length;
    uint8_t table[14];
} sys_desc_table_t;

typedef struct [[gnu::packed]] {
    uint32_t ofw_magic;
    uint32_t ofw_version;
    uint32_t cif_handler;
    uint32_t irq_desc_table;
} olpc_ofw_header_t;

typedef struct [[gnu::packed]] {
    unsigned char dummy[128];
} edid_info_t;

typedef struct [[gnu::packed]] {
    uint32_t efi_loader_signature;
    uint32_t efi_systab;
    uint32_t efi_memdesc_size;
    uint32_t efi_memdesc_version;
    uint32_t efi_memmap;
    uint32_t efi_memmap_size;
    uint32_t efi_systab_hi;
    uint32_t efi_memmap_hi;
} efi_info_t;

typedef struct [[gnu::packed]] {
    uint64_t addr;
    uint64_t size;
    uint32_t type;
} boot_e820_entry_t;

typedef struct [[gnu::packed]] {
    uint16_t length;
    uint16_t info_flags;
    uint32_t num_default_cylinders;
    uint32_t num_default_heads;
    uint32_t sectors_per_track;
    uint64_t number_of_sectors;
    uint16_t bytes_per_sector;
    uint32_t dpte_ptr;
    uint16_t key;
    uint8_t device_path_info_length;
    uint8_t reserved2;
    uint16_t reserved3;
    uint8_t host_bus_type[4];
    uint8_t interface_type[8];
    union {
        struct [[gnu::packed]] {
            uint16_t base_address;
            uint16_t reserved1;
            uint16_t reserved2;
        } isa;
        struct [[gnu::packed]] {
            uint8_t bus;
            uint8_t slot;
            uint8_t function;
            uint8_t channel;
            uint32_t reserved;
        } pci;
        struct [[gnu::packed]] {
            uint64_t reserved;
        } ibnd;
        struct [[gnu::packed]] {
            uint64_t reserved;
        } xprs;
        struct [[gnu::packed]] {
            uint64_t reserved;
        } htpt;
        struct [[gnu::packed]] {
            uint64_t reserved;
        } unknown;
    } interface_path;
    union {
        struct [[gnu::packed]] {
            uint8_t device;
            uint8_t reserved1;
            uint16_t reserved2;
            uint16_t reserved3;
            uint16_t reserved4;
        } ata;
        struct [[gnu::packed]] {
            uint8_t device;
            uint8_t lun;
            uint8_t reserved1;
            uint8_t reserved2;
            uint8_t reserved3;
            uint8_t reserved4;
        } atapi;
        struct [[gnu::packed]] {
            uint64_t serial_number;
            uint64_t reserved;
        } usb;
        struct [[gnu::packed]] {
            uint64_t eui;
            uint64_t reserved;
        } i1394;
        struct [[gnu::packed]] {
            uint64_t wwid;
            uint64_t lun;
        } fibre;
        struct [[gnu::packed]] {
            uint64_t identity_tag;
            uint64_t reserved;
        } i2o;
        struct [[gnu::packed]] {
            uint32_t array_number;
            uint32_t reserved1;
            uint32_t reserved2;
        } raid;
        struct [[gnu::packed]] {
            uint8_t device;
            uint8_t reserved1;
            uint8_t reserved2;
            uint8_t reserved3;
            uint8_t reserved4;
        } sata;
        struct [[gnu::packed]] {
            uint64_t reserved1;
            uint64_t reserved2;
        } unknown;
    } device_path;
    uint8_t reserved4;
    uint8_t checksum;
} edd_device_params_t;

typedef struct [[gnu::packed]] {
    uint8_t device;
    uint8_t version;
    uint16_t interface_support;
    uint16_t legacy_max_cylinder;
    uint8_t legacy_max_head;
    uint8_t legacy_sectors_per_track;
    edd_device_params_t params;
} edd_info_t;

typedef struct [[gnu::packed, gnu::aligned(4096)]] {
    screen_info_t screen_info;
    apm_bios_info_t apm_bios_info;
    uint8_t pad2[4];
    uint64_t tboot_addr;
    ist_info_t ist_info;
    uint64_t acpi_rsdp_addr;
    uint8_t pad3[8];
    uint8_t hd0_info[16];
    uint8_t hd1_info[16];
    sys_desc_table_t sys_desc_table;
    olpc_ofw_header_t olpc_ofw_header;
    uint32_t ext_ramdisk_image;
    uint32_t ext_ramdisk_size;
    uint32_t ext_cmd_line_ptr;
    uint8_t pad4[112];
    uint32_t cc_blob_address;
    edid_info_t edid_info;
    efi_info_t efi_info;
    uint32_t alt_mem_k;
    uint32_t scratch;
    uint8_t e820_entries;
    uint8_t eddbuf_entries;
    uint8_t edd_mbr_sig_buf_entries;
    uint8_t kbd_status;
    uint8_t secure_boot;
    uint8_t pad5[2];
    uint8_t sentinel;
    uint8_t pad6[1];
    setup_info_t setup_info;
    uint8_t pad7[159 - sizeof(setup_info_t)];
    uint32_t edd_mbr_sig_buffer[16];
    boot_e820_entry_t e820_table[128];
    uint8_t pad8[48];
    edd_info_t eddbuf[6];
    uint8_t pad9[276];
} boot_params_t;

#define LINUX_OLD_MAGIC 0xaa55
#define LINUX_MAGIC 0x53726448

#define PROTOCOL_2_05 0x205

#define LINUX_LOADFLAGS_QUIET (1u << 5)
#define LINUX_LOADFLAGS_KEEP_SEGMENTS (1u << 6)
#define LINUX_LOADFLAGS_CAN_USE_HEAP (1u << 7)
