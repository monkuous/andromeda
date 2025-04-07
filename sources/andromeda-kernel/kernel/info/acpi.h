#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *acpi_find_rsdp(uint64_t *phys_out, size_t *length_out);
