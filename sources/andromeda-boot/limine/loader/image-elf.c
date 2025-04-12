#include "image-elf.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "memory.h"
#include "paging.h"
#include "utils.h"
#include <elf.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const uint8_t wanted_ident[] = {
        ELFMAG0,
        ELFMAG1,
        ELFMAG2,
        ELFMAG3,
        ELFCLASS64,
        ELFDATA2LSB,
        EV_CURRENT,
};

#define WANTED_MACHINE EM_X86_64

static bool verify_offsets(Elf64_Ehdr *header) {
    if (header->e_phnum) {
        uint64_t phend = header->e_phoff + (uint64_t)header->e_phnum * header->e_phentsize - 1;
        if (phend < header->e_phoff || phend >= kernel_size) return false;

        for (uint64_t i = 0; i < header->e_phnum; i++) {
            Elf64_Phdr *phdr = kernel_image + header->e_phoff + i * header->e_phentsize;

            if (phdr->p_filesz) {
                uint64_t end = phdr->p_offset + phdr->p_filesz - 1;
                if (end < phdr->p_offset || end >= kernel_size) return false;
            }
        }
    }

    if (header->e_shnum) {
        if (header->e_shstrndx >= header->e_shnum) return false;

        uint64_t shend = header->e_shoff + (uint64_t)header->e_shnum * header->e_shentsize - 1;
        if (shend < header->e_shoff || shend >= kernel_size) return false;

        for (uint64_t i = 0; i < header->e_shnum; i++) {
            Elf64_Shdr *shdr = kernel_image + header->e_shoff + i * header->e_shentsize;

            if (shdr->sh_type != SHT_NOBITS && shdr->sh_size) {
                uint64_t end = shdr->sh_offset + shdr->sh_size - 1;
                if (end < shdr->sh_offset || end >= kernel_size) return false;
            }
        }
    }

    return true;
}

void init_elf() {
    if (kernel_size < sizeof(Elf64_Ehdr) || memcmp(kernel_image, wanted_ident, sizeof(wanted_ident))) {
        fprintf(stderr, "%s: invalid kernel image\n", progname);
        exit(1);
    }

    Elf64_Ehdr *header = kernel_image;

    if ((header->e_type != ET_EXEC && header->e_type != ET_DYN) || header->e_machine != WANTED_MACHINE ||
        header->e_version != EV_CURRENT || !verify_offsets(header)) {
        fprintf(stderr, "%s: invalid kernel image\n", progname);
        exit(1);
    }
}

static uint64_t slide;

static void perform_relocations(Elf64_Dyn *dynamic, void *ptr, uint64_t min_addr) {
    void *rela = nullptr;
    uint64_t relasz = 0;
    uint64_t relaent = 0;

    while (dynamic->d_tag != DT_NULL) {
        switch (dynamic->d_tag) {
        case DT_RELA: rela = ptr + (dynamic->d_un.d_ptr - min_addr); break;
        case DT_RELASZ: relasz = dynamic->d_un.d_val; break;
        case DT_RELAENT: relaent = dynamic->d_un.d_val; break;
        }
    }

    if (!rela) return;

    while (relasz >= relaent) {
        Elf64_Rela *cur = rela;

        void *dest = ptr + (cur->r_offset - min_addr);
        uint64_t type = ELF64_R_TYPE(cur->r_info);

        switch (type) {
        case R_X86_64_NONE: break;
        case R_X86_64_RELATIVE: *(uint64_t *)dest = slide + cur->r_addend; break;
        default: fprintf(stderr, "%s: unknown ELF relocation type: %llu\n", progname, type); exit(1);
        }

        rela += relaent;
        relasz -= relaent;
    }
}

void load_elf() {
    Elf64_Ehdr *header = kernel_image;

    uint64_t min_addr = UINT64_MAX;
    uint64_t max_addr = 0;

    for (uint64_t i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr *phdr = kernel_image + header->e_phoff + i * header->e_phentsize;
        if (phdr->p_type != PT_LOAD) continue;
        if (!phdr->p_memsz) continue;
        if (!(phdr->p_flags & (PF_R | PF_W | PF_X))) continue;

        uint64_t min = phdr->p_vaddr & ~0xfff;
        uint64_t max = (phdr->p_vaddr + phdr->p_memsz - 1) | 0xfff;

        if (min < min_addr) min_addr = min;
        if (max > max_addr) max_addr = max;
    }

    if (min_addr > max_addr) return; // Nothing to load

    paddr_t pbase = UINT64_MAX;
    void *ptr = alloc_pages(&pbase, max_addr - min_addr + 1, 0x1000, LIMINE_MEMORY_KERNEL);

    uint64_t vbase = min_addr;

    if (vbase < MIN_KERNEL_BASE_ADDR) {
        if (header->e_type == ET_EXEC) {
            fprintf(stderr, "%s: refusing to load non-relocatable lower half executable\n", progname);
            exit(1);
        }

        vbase = MIN_KERNEL_BASE_ADDR;
    }

    slide = vbase - min_addr;

    printf("loading executable\n");

    Elf64_Phdr *dynamic = nullptr;

    for (uint64_t i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr *phdr = kernel_image + header->e_phoff + i * header->e_phentsize;
        if (phdr->p_type != PT_LOAD) {
            if (phdr->p_type == PT_DYNAMIC) dynamic = phdr;
            continue;
        }

        if (!phdr->p_memsz) continue;
        if (!(phdr->p_flags & (PF_R | PF_W | PF_X))) continue;

        void *sptr = ptr + (phdr->p_vaddr - min_addr);

        if (phdr->p_filesz) {
            memcpy(sptr, kernel_image + phdr->p_offset, phdr->p_filesz);
        }

        if (phdr->p_filesz < phdr->p_memsz) {
            memset(sptr + phdr->p_filesz, 0, phdr->p_memsz - phdr->p_filesz);
        }

        uint64_t page_offset = phdr->p_vaddr & 0xfff;
        uint64_t map_offset = (phdr->p_vaddr - page_offset) - min_addr;
        uint64_t map_size = (phdr->p_memsz + page_offset + 0xfff) & ~0xfff;
        int map_flags = 0;

        if (phdr->p_flags & PF_W) map_flags |= PAGE_WRITABLE;
        if (phdr->p_flags & PF_X) map_flags |= PAGE_EXECUTABLE;

        paging_map(vbase + map_offset, pbase + map_offset, map_size, map_flags);
    }

    if (dynamic) {
        perform_relocations(ptr + (dynamic->p_vaddr - min_addr), ptr, min_addr);
    }

    boot_info.entry_point = header->e_entry + slide;
    boot_info.responses.executable_address.physical_base = pbase;
    boot_info.responses.executable_address.virtual_base = vbase;
}

uint64_t elf_offset_to_virt(uint64_t offset) {
    Elf64_Ehdr *header = kernel_image;

    for (uint64_t i = 0; i < header->e_phnum; i++) {
        Elf64_Phdr *phdr = kernel_image + header->e_phoff + i * header->e_phentsize;
        if (phdr->p_type != PT_LOAD) continue;
        if (offset < phdr->p_offset) continue;

        uint64_t soffset = offset - phdr->p_offset;
        if (soffset < phdr->p_filesz) return phdr->p_vaddr + soffset + slide;
    }

    fprintf(stderr, "%s: failed to convert offset 0x%llx to vaddr\n", progname, offset);
    exit(1);
}
