#pragma once

#include <stdint.h>

typedef struct [[gnu::packed]] {
    uint16_t pixel_clock;
    uint8_t width_low;
    uint8_t hblank_low;
    uint8_t width_hblank_high;
    uint8_t height_low;
    uint8_t vblank_low;
    uint8_t height_vblank_high;
    uint8_t hporch_low;
    uint8_t hsyncw_low;
    uint8_t vporch_vsyncw_low;
    uint8_t porch_syncw_high;
    uint8_t hsize_low;
    uint8_t vsize_low;
    uint8_t size_high;
    uint8_t hborder;
    uint8_t vborder;
    uint8_t flags;
} timing_desc_t;

typedef struct [[gnu::packed]] {
    uint8_t header[8];
    uint16_t manufacturer;
    uint16_t product_code;
    uint32_t serial_number;
    uint8_t manufacture_week;
    uint8_t manufacture_year;
    uint8_t edid_version;
    uint8_t edid_revision;
    uint8_t input_definition;
    uint8_t max_horiz_size;
    uint8_t max_vert_size;
    uint8_t gamma;
    uint8_t features;
    uint8_t chroma[10];
    uint8_t timing_bitmap[3];
    uint16_t std_timings[8];
    timing_desc_t pref_timing;
    timing_desc_t descriptors[3];
    uint8_t extensions;
    uint8_t checksum;
} edid_t;
