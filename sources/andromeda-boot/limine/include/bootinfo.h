#pragma once

#include "limine.h"
#include <stdint.h>

#define BOOT_INFO_SETUP_PAT 1

// This is passed to the prekernel.
// Note that the prekernel might be using a different ABI than us,
// so all fields must transitively consist of fixed-width types,
// and there must be no padding (except at the end).
typedef struct {
    uint64_t entry_point;
    uint64_t mp_response_field_ptr;
    uint64_t gdt[7];
    struct {
        struct limine_paging_mode_response paging_mode;
        struct limine_stack_size_response stack_size;
        struct limine_hhdm_response hhdm;
        struct limine_executable_address_response executable_address;
        struct limine_entry_point_response entry_point;
        struct limine_framebuffer_response framebuffer;
        struct limine_memmap_response memmap;
        struct limine_rsdp_response rsdp;
        struct limine_module_response module;
        struct limine_executable_file_response executable_file;
        struct limine_executable_cmdline_response executable_cmdline;
        struct limine_mp_response mp;
    } responses;
    uint32_t flags;
    uint32_t pt_levels;
    uint32_t mp_low_page;
    uint32_t mp_flags;
    uint32_t mp_stack_pages;
} boot_info_t;
