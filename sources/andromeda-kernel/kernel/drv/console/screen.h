#pragma once

#include <stdint.h>

#define SCREEN_WIDTH 80
#define SCREEN_HEIGHT 25

void screen_init();
void screen_reset();
void screen_set_char(unsigned x, unsigned y, uint16_t value);
uint16_t screen_get_char(unsigned x, unsigned y);
void screen_set_cursor_enabled(bool enabled);
void screen_set_cursor_pos(unsigned x, unsigned y);
void screen_flush();

uint8_t screen_map_unicode(uint32_t codepoint);
