#pragma once

#include <elf.h>
#include <stddef.h>
#include <stdint.h>

void init_elf();
void load_elf();
uint64_t elf_offset_to_virt(uint64_t offset);
