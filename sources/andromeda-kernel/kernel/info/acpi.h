#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

void *acpi_find_rsdp(size_t *length_out);
