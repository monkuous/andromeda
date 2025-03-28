#pragma once

#include <stddef.h>
#include <stdint.h>

static inline uint32_t make_hash_int32(uint32_t x) {
    x ^= x >> 16;
    x *= 0x7feb352d;
    x ^= x >> 15;
    x *= 0x846ca68b;
    x ^= x >> 16;
    return x;
}

static inline uint32_t make_hash_blob(const void *data, size_t length) {
    // FNV-1a
    const unsigned char *d = data;
    uint32_t hash = 0x811c9dc5;

    while (length--) {
        hash ^= *d++;
        hash *= 0x01000193;
    }

    return hash;
}
