#pragma once

#include <stdint.h>

void init_image();
void load_image();
uint64_t offset_to_virt(uint64_t offset);
