#pragma once

#include "drv/device.h"
#include <stdint.h>

void init_biosdisk(uint8_t boot_drive, uint64_t boot_lba);

bdev_t *resolve_biosdisk(uint32_t id);
