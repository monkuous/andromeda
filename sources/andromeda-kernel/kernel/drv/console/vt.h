#pragma once

#include <stdint.h>

void vt_init();
void vt_reset();
void vt_write_byte(uint8_t value);
bool vt_read_byte(uint8_t *out);
void vt_backspace();
