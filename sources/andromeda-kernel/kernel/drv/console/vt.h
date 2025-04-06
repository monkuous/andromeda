#pragma once

#include <stdint.h>

typedef struct {
    unsigned x, y;
    uint16_t attributes;
    bool reverse_colors : 1;
} vt_state_t;

extern vt_state_t vt_state;

void vt_init();
void vt_reset();
void vt_write_byte(uint8_t value);
bool vt_read_byte(uint8_t *out);
void vt_backspace();
