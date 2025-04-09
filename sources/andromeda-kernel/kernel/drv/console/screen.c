#include "screen.h"
#include "compiler.h"
#include "init/bios.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmem.h"
#include "util/panic.h"
#include <stddef.h>
#include <stdint.h>

#define CURSOR_CHAR 0xdb

// video memory fields
static volatile uint16_t *video_memory;
static struct {
    uint16_t value;
    short queue_idx;
} vidmem_buffer[SCREEN_WIDTH * SCREEN_HEIGHT];
static struct {
    uint16_t value;
    short vidmem_idx;
} vidmem_queue[SCREEN_WIDTH * SCREEN_HEIGHT];
static int queue_count;

// cursor fields
static unsigned cur_x, cur_y;
static unsigned prev_x, prev_y;
static bool cur_enabled, prev_enabled;
static uint16_t cur_covered;

static bool screen_enabled;

void screen_init() {
    // map video memory
    size_t map_size = (SCREEN_WIDTH * SCREEN_HEIGHT * 2 + PAGE_MASK) & ~PAGE_MASK;
    uintptr_t vaddr = vmem_alloc(map_size);
    pmap_map(vaddr, 0xb8000, map_size, PMAP_WRITABLE);
    video_memory = (void *)vaddr;

    screen_reset();
    screen_set_cursor_enabled(false);
    screen_enable(true);
}

static uint16_t vidmem_read(int x, int y) {
    int idx = y * SCREEN_WIDTH + x;
    int qi = vidmem_buffer[idx].queue_idx - 1;

    if (qi >= 0) {
        return vidmem_queue[qi].value;
    }

    return vidmem_buffer[idx].value;
}

static void vidmem_write(int x, int y, uint16_t value) {
    int idx = y * SCREEN_WIDTH + x;
    int qi = vidmem_buffer[idx].queue_idx - 1;

    if (qi < 0) {
        if (value == vidmem_buffer[idx].value) return;
        qi = queue_count++;
        vidmem_buffer[idx].queue_idx = qi + 1;
        vidmem_queue[qi].vidmem_idx = idx;
    }

    vidmem_queue[qi].value = value;
}

static void vidmem_flush() {
    if (!screen_enabled) return;

    for (int i = 0; i < queue_count; i++) {
        uint16_t val = vidmem_queue[i].value;
        int idx = vidmem_queue[i].vidmem_idx;

        if (val != vidmem_buffer[idx].value) {
            vidmem_buffer[idx].value = val;
            video_memory[idx] = val;
        }

        vidmem_buffer[idx].queue_idx = 0;
    }

    queue_count = 0;
}

void screen_disable() {
    screen_enabled = false;
}

void screen_enable(bool restore) {
    if (screen_enabled) return;

    if (restore) {
        // ensure video mode is 3 (80x25 color text)
        regs_t regs = (regs_t){.eax = 3};
        intcall(0x10, &regs);

        // disable cursor
        regs = (regs_t){.eax = 0x100, .ecx = 0x2f0f};
        intcall(0x10, &regs);

        // synchronize video memory
        for (int i = 0; i < SCREEN_WIDTH * SCREEN_HEIGHT; i++) {
            video_memory[i] = vidmem_buffer[i].value;
        }
    }

    screen_enabled = true;
    vidmem_flush();
}

void screen_reset() {
    cur_x = cur_y = 0;
    cur_enabled = true;

    for (int y = 0; y < SCREEN_HEIGHT; y++) {
        for (int x = 0; x < SCREEN_WIDTH; x++) {
            screen_set_char(x, y, 0x720);
        }
    }

    vidmem_flush();
}

void screen_set_char(unsigned x, unsigned y, uint16_t value) {
    ASSERT(x < SCREEN_WIDTH && y < SCREEN_HEIGHT);

    if (!prev_enabled || x != prev_x || y != prev_y) vidmem_write(x, y, value);
    else cur_covered = value;
}

uint16_t screen_get_char(unsigned x, unsigned y) {
    ASSERT(x < SCREEN_WIDTH && y < SCREEN_HEIGHT);

    if (prev_enabled && x == prev_x && y == prev_y) return cur_covered;
    return vidmem_read(x, y);
}

void screen_set_cursor_enabled(bool enabled) {
    cur_enabled = enabled;
}

void screen_set_cursor_pos(unsigned x, unsigned y) {
    ASSERT(x < SCREEN_WIDTH && y < SCREEN_HEIGHT);
    cur_x = x;
    cur_y = y;
}

static void update_cursor() {
    if (cur_enabled) {
        if (prev_enabled) {
            vidmem_write(prev_x, prev_y, cur_covered);
        } else {
            prev_enabled = true;
        }

        prev_x = cur_x;
        prev_y = cur_y;

        cur_covered = vidmem_read(cur_x, cur_y);
        vidmem_write(cur_x, cur_y, (cur_covered & 0xff00) | CURSOR_CHAR);
    } else if (prev_enabled) {
        prev_enabled = false;
        vidmem_write(prev_x, prev_y, cur_covered);
    }
}

void screen_flush() {
    update_cursor();
    vidmem_flush();
}

// from https://en.wikipedia.org/wiki/Code_page_437
// skips over 0x20..0x7e, which are identical in cp437 and unicode
static const uint16_t cp437_to_unicode[0x100 - (0x7f - 0x20)] = {
        0x20,   0x263a, 0x263b, 0x2665, 0x2666, 0x2663, 0x2660, 0x2022, 0x25d8, 0x25cb, 0x25d9, 0x2642, 0x2640, 0x266a,
        0x266b, 0x263c, 0x25ba, 0x25c4, 0x2195, 0x203c, 0xb6,   0xa7,   0x25ac, 0x21a8, 0x2191, 0x2193, 0x2192, 0x2190,
        0x221f, 0x2194, 0x25b2, 0x25bc, 0x2302, 0xc7,   0xfc,   0xe9,   0xe2,   0xe4,   0xe0,   0xe5,   0xe7,   0xea,
        0xeb,   0xe8,   0xef,   0xee,   0xec,   0xc4,   0xc5,   0xc9,   0xe6,   0xc6,   0xf4,   0xf6,   0xf2,   0xfb,
        0xf9,   0xff,   0xd6,   0xdc,   0xa2,   0xa3,   0xa5,   0x20a7, 0x192,  0xe1,   0xed,   0xf3,   0xfa,   0xf1,
        0xd1,   0xaa,   0xba,   0xbf,   0x2310, 0xac,   0xbd,   0xbc,   0xa1,   0xab,   0xbb,   0x2591, 0x2592, 0x2593,
        0x2502, 0x2524, 0x2561, 0x2562, 0x2556, 0x2555, 0x2563, 0x2551, 0x2557, 0x255d, 0x255c, 0x255b, 0x2510, 0x2514,
        0x2534, 0x252c, 0x251c, 0x2500, 0x253c, 0x255e, 0x255f, 0x255a, 0x2554, 0x2569, 0x2566, 0x2560, 0x2550, 0x256c,
        0x2567, 0x2568, 0x2564, 0x2565, 0x2559, 0x2558, 0x2552, 0x2553, 0x256b, 0x256a, 0x2518, 0x250c, 0x2588, 0x2584,
        0x258c, 0x2590, 0x2580, 0x3b1,  0xdf,   0x393,  0x3c0,  0x3a3,  0x3c3,  0xb5,   0x3c4,  0x3a6,  0x398,  0x3a9,
        0x3b4,  0x221e, 0x3c6,  0x3b5,  0x2229, 0x2261, 0xb1,   0x2265, 0x2264, 0x2320, 0x2321, 0xf7,   0x2248, 0xb0,
        0x2219, 0xb7,   0x221a, 0x207f, 0xb2,   0x25a0, 0x20
};

uint8_t screen_map_unicode(uint32_t unicode) {
    if (likely(unicode >= 0x20 && unicode <= 0x7e)) return unicode;

    for (unsigned i = 0; i < sizeof(cp437_to_unicode) / sizeof(*cp437_to_unicode); i++) {
        if (cp437_to_unicode[i] == unicode) {
            if (i >= 0x20) i += 0x7f - 0x20;
            return i;
        }
    }

    // special case some characters that aren't encodable in CP437
    // but have a closely matching equivalent
    switch (unicode) {
    case 0x2018:
    case 0x2019: return '\'';
    default: return '?';
    }
}
