#include "vt.h"
#include "drv/console/keyboard.h"
#include "drv/console/screen.h"
#include "init/bios.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

#if 1
static void on_invalid() {
}

#define INVALID_ESCAPE(x)                                                                                              \
    ({                                                                                                                 \
        printk("vt: unknown escape byte 0x%x during %s\n", (x), __func__);                                             \
        on_invalid();                                                                                                  \
    })
#define INVALID_PARAM(x)                                                                                               \
    ({                                                                                                                 \
        printk("vt: unknown parameter 0x%x during %s\n", (x), __func__);                                               \
        on_invalid();                                                                                                  \
    })
#else
#define INVALID_ESCAPE(x) ((void)0)
#define INVALID_PARAM(x) ((void)0)
#endif

#define ESC_MAX_PARAMS 16
#define BLANK_CHAR ' '
#define DEFAULT_ATTR 0x700

typedef enum {
    ESC_NONE,
    ESC_INIT,
    ESC_SET_CHARSET,
    ESC_ALIGN_TEST,
    ESC_SET_G0,
    ESC_SET_G1,
    ESC_OSC,
    ESC_OSC_PALETTE,
    ESC_GET_PARAMS,
    ESC_PARAM_IGNORE,
    ESC_CSI_START,
    ESC_CSI,
    ESC_CSI_DEC,
    ESC_IGNORE_ONE,
} escape_state_t;

static escape_state_t esc_state;
static escape_state_t esc_get_params_next;
static unsigned esc_params[ESC_MAX_PARAMS];
static unsigned esc_nparam;

#define MODE_DISPLAY_CONTROL 1
#define MODE_INSERT 2
#define MODE_AUTO_CR 4
#define MODE_CURSOR_APPLICATION 8
#define MODE_REVERSE_VIDEO 16
#define MODE_SCROLL_RELATIVE 32
#define MODE_AUTO_WRAP 64
#define MODE_AUTO_REPEAT 128
#define MODE_CURSOR_VISIBLE 256
#define MODE_KEYPAD_APPLICATION 512

#define DEFAULT_MODE (MODE_AUTO_REPEAT | MODE_AUTO_WRAP | MODE_CURSOR_VISIBLE)

vt_state_t vt_state;
static vt_state_t saved_state;
static unsigned mode;
static unsigned base_y, base_height;
static unsigned scroll_y0, scroll_y1;
static uint32_t tab_stops[(SCREEN_WIDTH + 31) / 32];

static bool have_repeat_control;

static void inject_input(const void *, size_t);

static uint16_t cp_to_val(uint32_t cp) {
    return vt_state.attributes | screen_map_unicode(cp);
}

static uint16_t do_reverse(uint16_t val) {
    return (val & 0xff) | ((val & 0xf000) >> 4) | ((val & 0x0f00) << 4);
}

static uint16_t maybe_reverse(uint16_t val) {
    if (mode & MODE_REVERSE_VIDEO) {
        return do_reverse(val);
    }

    return val;
}

static void do_set_char(unsigned x, unsigned y, uint16_t value) {
    screen_set_char(x, y, maybe_reverse(value));
}

static void set_new_char(unsigned x, unsigned y, uint16_t value) {
    if (vt_state.reverse_colors) value = do_reverse(value);
    screen_set_char(x, y, value);
}

static void update_autorepeat() {
    if (!have_repeat_control) return;

    if (mode & MODE_AUTO_REPEAT) {
        regs_t regs = {.eax = 0x300}; /* set default rate and delay */
        intcall(0x16, &regs);
    } else {
        /* turn off repeat. not widely supported, but if it fails
           we don't have any other options anyway. might as well try. */
        regs_t regs = {.eax = 0x304};
        intcall(0x16, &regs);
    }
}

static void update_mode(unsigned new_mode) {
    if (!(new_mode & MODE_KEYPAD_APPLICATION)) {
        new_mode &= ~MODE_CURSOR_APPLICATION;
    }

    unsigned old_mode = mode;
    mode = new_mode;

    if ((old_mode & MODE_REVERSE_VIDEO) != (new_mode & MODE_REVERSE_VIDEO)) {
        for (unsigned y = 0; y < SCREEN_HEIGHT; y++) {
            for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
                do_set_char(x, y, screen_get_char(x, y));
            }
        }
    }

    if ((old_mode & MODE_SCROLL_RELATIVE) != (new_mode & MODE_SCROLL_RELATIVE)) {
        if (new_mode & MODE_SCROLL_RELATIVE) {
            base_y = scroll_y0;
            base_height = scroll_y1 - scroll_y0;
        } else {
            base_y = 0;
            base_height = SCREEN_HEIGHT;
        }

        vt_state.x = vt_state.y = 0;
    }

    if ((old_mode & MODE_AUTO_REPEAT) != (new_mode & MODE_AUTO_REPEAT)) {
        update_autorepeat();
    }
}

static void maybe_scroll() {
    if (vt_state.y + base_y >= scroll_y1) {
        ASSERT(vt_state.y + base_y == scroll_y1);
        vt_state.y -= 1;

        uint16_t val = cp_to_val(BLANK_CHAR);

        for (unsigned y = scroll_y0 + 1; y < scroll_y1; y++) {
            for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
                screen_set_char(x, y - 1, screen_get_char(x, y));
            }
        }

        for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
            do_set_char(x, scroll_y1 - 1, val);
        }
    }
}

static void emit_lf() {
    if (mode & MODE_AUTO_CR) vt_state.x = 0;
    vt_state.y += 1;
    maybe_scroll();
}

static void set_tab_stop(int column) {
    tab_stops[column / 32] |= 1ul << (column % 32);
}

static void clear_tab_stop(int column) {
    tab_stops[column / 32] &= ~(1ul << (column % 32));
}

static void inject_id() {
    inject_input("\x1b?6c", 4);
}

static void save_state() {
    saved_state = vt_state;
}

static void restore_state() {
    vt_state = saved_state;
    if (vt_state.y >= base_height) vt_state.y = base_height - 1;
}

static void reverse_lf() {
    if (vt_state.y + base_y == scroll_y0) {
        ASSERT(vt_state.y + base_y == scroll_y0);

        uint16_t val = cp_to_val(BLANK_CHAR);

        for (unsigned y = scroll_y1 - 1; y > scroll_y0; y--) {
            for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
                screen_set_char(x, y, screen_get_char(x, y - 1));
            }
        }

        for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
            do_set_char(x, scroll_y0, val);
        }
    } else if (vt_state.y > 0) {
        vt_state.y -= 1;
    }
}

static void process_esc_init(uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case 'c': vt_reset(); break;
    case 'D':
    case 'E': emit_lf(); break;
    case 'H': set_tab_stop(vt_state.x); break;
    case 'M':
        reverse_lf();
        if (vt_state.y > 0) vt_state.y -= 1;
        break;
    case 'Z': inject_id(); break;
    case '7': save_state(); break;
    case '8': restore_state(); break;
    case '%': esc_state = ESC_SET_CHARSET; break;
    case '#': esc_state = ESC_ALIGN_TEST; break;
    case '(': esc_state = ESC_SET_G0; break;
    case ')': esc_state = ESC_SET_G1; break;
    case '>': update_mode(mode & ~MODE_KEYPAD_APPLICATION); break;
    case '=': update_mode(mode | MODE_KEYPAD_APPLICATION); break;
    case ']': esc_state = ESC_OSC; break;
    case '[': esc_state = ESC_CSI_START; break;
    default: INVALID_ESCAPE(cp); break;
    }
}

static void process_esc_set_charset(uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case '@': break; // TODO: Select ISO 8859-1
    case 'G':
    case '8': break; // TODO: Select UTF-8
    default: INVALID_ESCAPE(cp); break;
    }
}

static void process_esc_align_test(uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case '8':
        for (int y = 0; y < SCREEN_HEIGHT; y++) {
            for (int x = 0; x < SCREEN_WIDTH; x++) {
                do_set_char(x, y, vt_state.attributes | 'E');
            }
        }
        break;
    default: INVALID_ESCAPE(cp); break;
    }
}

static void process_esc_set_g(int, uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case 'B': break; // TODO: Set default (ISO 8859-1 to CP-437)
    case '0': break; // TODO: Set VT100 mapping
    case 'U': break; // TODO: Set null mapping
    case 'K': break; // TODO: Set user mapping
    default: INVALID_ESCAPE(cp); break;
    }
}

static void process_esc_osc(uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case 'R': break; // Reset palette. This is meaningless for us.
    case 'P':
        esc_state = ESC_OSC_PALETTE;
        esc_nparam = 0;
        break;
    default: INVALID_ESCAPE(cp); break;
    }
}

static bool is_hex(uint32_t cp) {
    return (cp >= '0' && cp <= '9') || ((cp | 0x20) >= 'a' && (cp | 0x20) <= 'f');
}

static void process_esc_osc_palette(uint32_t cp) {
    // The palette is not configurable, so just confirm validity and discard the data
    if (!is_hex(cp)) {
        INVALID_ESCAPE(cp);
        esc_state = ESC_NONE;
    } else if (esc_nparam++ == 7) {
        esc_state = ESC_NONE;
    }
}

static void process_escape(uint32_t cp);

static void process_esc_get_params(uint32_t cp) {
    if (!esc_nparam) esc_params[esc_nparam++] = 0;

    switch (cp) {
    case ';':
        if (esc_nparam < ESC_MAX_PARAMS) {
            esc_params[esc_nparam++] = 0;
            return;
        }
        break;
    case '0' ... '9':
        esc_params[esc_nparam - 1] *= 10;
        esc_params[esc_nparam - 1] += cp - '0';
        return;
    default:
        if (cp >= 0x20 && cp <= 0x3f) {
            esc_state = ESC_PARAM_IGNORE;
            return;
        }

        esc_state = esc_get_params_next;
        return process_escape(cp);
    }
}

static void process_esc_param_ignore(uint32_t cp) {
    if (cp < 0x20 || cp > 0x3f) {
        esc_state = ESC_IGNORE_ONE;
    }
}

static unsigned get_esc_param(unsigned i, unsigned def) {
    if (i >= esc_nparam || !esc_params[i]) return def;
    return esc_params[i];
}

static void process_esc_csi_start(uint32_t cp) {
    esc_state = ESC_GET_PARAMS;
    esc_nparam = 0;

    switch (cp) {
    case '[': esc_state = ESC_IGNORE_ONE; return;
    case '?': esc_get_params_next = ESC_CSI_DEC; return;
    default: esc_get_params_next = ESC_CSI; return process_esc_get_params(cp);
    }
}

static unsigned clamp(unsigned val, unsigned min, unsigned max) {
    if (val < min) return min;
    if (val > max) return max;
    return val;
}

static void insert_chars(unsigned count) {
    unsigned avail = SCREEN_WIDTH - vt_state.x;
    if (count > avail) count = avail;

    uint16_t val = cp_to_val(BLANK_CHAR);
    unsigned rem = avail - count;

    unsigned x = SCREEN_WIDTH - 1;

    for (unsigned i = rem; i > 0; i--, x--) {
        if (i > count) screen_set_char(x, vt_state.y + base_y, screen_get_char(x - count, vt_state.y + base_y));
        else do_set_char(x, vt_state.y + base_y, val);
    }
}

static void incr_coord(unsigned *coord, unsigned max, int delta) {
    unsigned cur = *coord;

    if (delta < 0) {
        if ((unsigned)-delta >= cur) {
            *coord = 0;
            return;
        }
    } else if ((unsigned)delta >= max - cur) {
        *coord = max - 1;
        return;
    }

    *coord = cur + delta;
}

static void erase_screen(unsigned type) {
    uint16_t val = cp_to_val(BLANK_CHAR);

    switch (type) {
    case 0: {
        unsigned x = vt_state.x;

        for (unsigned y = vt_state.y + base_y; y < SCREEN_HEIGHT; y++) {
            for (; x < SCREEN_WIDTH; x++) {
                do_set_char(x, y, val);
            }

            x = 0;
        }
        break;
    }
    case 1:
        for (unsigned y = 0; y < vt_state.y + base_y; y++) {
            for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
                do_set_char(x, y, val);
            }
        }

        for (unsigned x = 0; x < vt_state.x; x++) {
            do_set_char(x, vt_state.y, val);
        }
        break;
    case 2:
    case 3:
        for (unsigned y = 0; y < SCREEN_HEIGHT; y++) {
            for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
                do_set_char(x, y, val);
            }
        }
        break;
    default: INVALID_PARAM(type); return;
    }
}

static void erase_line(unsigned type) {
    if (type > 2) {
        INVALID_PARAM(type);
        return;
    }

    uint16_t val = cp_to_val(BLANK_CHAR);

    unsigned x = type == 0 ? vt_state.x : 0;
    unsigned max = type != 0 ? vt_state.x : SCREEN_WIDTH;

    for (; x < max; x++) {
        do_set_char(x, vt_state.y + base_y, val);
    }
}

static void insert_lines(unsigned count) {
    unsigned avail = base_height - vt_state.y;
    if (avail < count) count = avail;

    uint16_t val = cp_to_val(BLANK_CHAR);
    unsigned rem = avail - count;

    unsigned y = base_y + base_height - 1;

    for (unsigned i = rem; i > 0; i--, y--) {
        for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
            if (i > count) screen_set_char(x, y, screen_get_char(x, y - count));
            else do_set_char(x, y, val);
        }
    }
}

static void delete_lines(unsigned count) {
    unsigned avail = base_height - vt_state.y;
    if (avail < count) count = avail;

    uint16_t val = cp_to_val(BLANK_CHAR);
    unsigned rem = avail - count;

    unsigned i;
    unsigned y = vt_state.y + base_y;

    for (i = 0; i < rem; i++, y++) {
        for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
            screen_set_char(x, y, screen_get_char(x, y + count));
        }
    }

    for (; i < avail; i++, y++) {
        for (unsigned x = 0; x < SCREEN_WIDTH; x++) {
            do_set_char(x, y, val);
        }
    }
}

static void delete_chars(unsigned count) {
    unsigned avail = SCREEN_WIDTH - vt_state.x;
    if (avail < count) count = avail;

    uint16_t val = cp_to_val(BLANK_CHAR);
    unsigned rem = avail - count;

    unsigned i;
    unsigned x = vt_state.x;

    for (i = 0; i < rem; i++, x++) {
        screen_set_char(x, vt_state.y + base_y, screen_get_char(x + count, vt_state.y + base_y));
    }

    for (; i < avail; i++, x++) {
        do_set_char(x, vt_state.y + base_y, val);
    }
}

static void erase_chars(unsigned count) {
    unsigned avail = SCREEN_WIDTH - vt_state.x;
    if (avail > count) count = avail;

    uint16_t val = cp_to_val(BLANK_CHAR);
    unsigned x = vt_state.x;

    for (unsigned i = 0; i < count; i++, x++) {
        do_set_char(x, vt_state.y + base_y, val);
    }
}

static void remove_tab_stops(unsigned type) {
    switch (type) {
    case 0: clear_tab_stop(vt_state.x); break;
    case 3: memset(tab_stops, 0, sizeof(tab_stops)); break;
    default: INVALID_PARAM(type); return;
    }
}

static unsigned get_mode_mask() {
    unsigned mask = 0;

    for (unsigned i = 0; i < esc_nparam; i++) {
        unsigned param = get_esc_param(i, 0);

        switch (param) {
        case 3: mask |= MODE_DISPLAY_CONTROL; break;
        case 4: mask |= MODE_INSERT; break;
        case 20: mask |= MODE_AUTO_CR; break;
        default: INVALID_PARAM(param); break;
        }
    }

    return mask;
}

#define SET_FG(x) vt_state.attributes = (vt_state.attributes & 0xf000) | ((x) << 8)
#define SET_BG(x) vt_state.attributes = (vt_state.attributes & 0x0f00) | ((x) << 12)

static bool col256_to_rgb(unsigned value, uint8_t out[3]) {
    ASSERT(value >= 16);

    if (value < 232) {
        value -= 16;

        unsigned blue = value % 6;
        unsigned temp = value / 6;
        unsigned green = temp % 6;
        unsigned red = temp / 6;

        if (red) red = red * 40 + 55;
        if (green) green = green * 40 + 55;
        if (blue) blue = blue * 40 + 55;

        out[0] = red;
        out[1] = green;
        out[2] = blue;

        return true;
    }

    if (value >= 256) {
        INVALID_PARAM(value);
        return false;
    }

    value -= 232;

    unsigned level = value * 10 + 8;
    out[0] = level;
    out[1] = level;
    out[2] = level;
    return true;
}

static unsigned get_next_arg(unsigned *i) {
    if (*i + 1 >= esc_nparam) return 0;
    return esc_params[++*i];
}

static int color_to_out(unsigned color) {
    static const uint8_t table[16] = {0, 4, 2, 6, 1, 5, 3, 7, 8, 12, 10, 14, 9, 13, 11, 15};

    return table[color];
}

static unsigned rgb_dist(const uint8_t a[3], const uint8_t b[3]) {
    int d0 = (int)a[0] - b[0];
    int d1 = (int)a[1] - b[1];
    int d2 = (int)a[2] - b[2];
    return d0 * d0 + d1 * d1 + d2 * d2;
}

static int colext_to_out(unsigned *i) {
    static const uint8_t colors[16][3] = {
            {0x00, 0x00, 0x00},
            {0x00, 0x00, 0xc4},
            {0x00, 0xc4, 0x00},
            {0x00, 0xc4, 0xc4},
            {0xc4, 0x00, 0x00},
            {0xc4, 0x00, 0xc4},
            {0xc4, 0xc4, 0x00},
            {0xc4, 0xc4, 0xc4},
            {0x55, 0x55, 0x55},
            {0x55, 0x55, 0xff},
            {0x55, 0xff, 0x55},
            {0x55, 0xff, 0xff},
            {0xff, 0x55, 0x55},
            {0xff, 0x55, 0xff},
            {0xff, 0xff, 0x55},
            {0xff, 0xff, 0xff},
    };

    uint8_t color[3];

    unsigned type = get_next_arg(i);
    switch (type) {
    case 2:
        color[0] = clamp(get_next_arg(i), 0, 0xff);
        color[1] = clamp(get_next_arg(i), 0, 0xff);
        color[2] = clamp(get_next_arg(i), 0, 0xff);
        break;
    case 5: {
        unsigned input = get_next_arg(i);
        if (input < 16) return color_to_out(input);

        if (!col256_to_rgb(input, color)) return -1;
        break;
    }
    default: INVALID_PARAM(type); return -1;
    }

    int cur = 0;
    unsigned cur_dist = -1;

    for (int i = 0; i < 16; i++) {
        unsigned dist = rgb_dist(color, colors[i]);

        if (dist < cur_dist) {
            cur = i;
            cur_dist = dist;
        }
    }

    return cur;
}

static void set_attributes() {
    for (unsigned i = 0; i < esc_nparam; i++) {
        unsigned param = get_esc_param(i, 0);

        switch (param) {
        case 0:
            vt_state.attributes = DEFAULT_ATTR;
            vt_state.reverse_colors = false;
            break;
        case 7: vt_state.reverse_colors = true; break;
        case 27: vt_state.reverse_colors = false; break;
        case 30 ... 37: SET_FG(color_to_out(param - 30)); break;
        case 38: {
            int color = colext_to_out(&i);
            if (color < 0) return;
            SET_FG(color);
            break;
        }
        case 39: SET_FG(7); break; // set default
        case 40 ... 47:
        case 100 ... 107: SET_BG(color_to_out(param % 10)); break;
        case 48: {
            int color = colext_to_out(&i);
            if (color < 0) return;
            SET_BG(color);
            break;
        }
        case 49: SET_BG(7); break; // set default
        case 90 ... 97: SET_FG(color_to_out(param - 90 + 8)); break;
        default: INVALID_PARAM(param);
        }
    }
}

static void report_info(unsigned type) {
    switch (type) {
    case 5: inject_input("\x1b[0n", 4); break;
    case 6: {
        unsigned char buf[32];
        size_t length = snprintk(buf, sizeof(buf), "\x1b[%u;%uR", vt_state.x + 1, vt_state.y + 1);
        ASSERT(length <= sizeof(buf));
        inject_input(buf, length);
        break;
    }
    default: INVALID_PARAM(type); return;
    }
}

static void set_leds(unsigned type) {
    switch (type) {
    case 0: break; // clear all leds
    case 1: break; // set scroll lock
    case 2: break; // set num lock
    case 3: break; // set caps lock
    default: INVALID_PARAM(type); return;
    }
}

static void set_scroll_region(unsigned y0, unsigned y1) {
    if (y0 >= y1) return;

    scroll_y0 = y0;
    scroll_y1 = y1 + 1;
    vt_state.x = 0;
    vt_state.y = 0;

    if (mode & MODE_SCROLL_RELATIVE) {
        base_y = scroll_y0;
        base_height = scroll_y1 - scroll_y0;
    }
}

static void process_linux_command(unsigned type) {
    switch (type) {
    case 8: vt_state.attributes = DEFAULT_ATTR; return;
    default: INVALID_PARAM(type); return;
    }
}

static void process_esc_csi(uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case '@': return insert_chars(get_esc_param(0, 1));
    case 'A': return incr_coord(&vt_state.y, base_height, -(int)get_esc_param(0, 1));
    case 'e':
    case 'B': return incr_coord(&vt_state.y, base_height, get_esc_param(0, 1));
    case 'a':
    case 'C': return incr_coord(&vt_state.x, SCREEN_WIDTH, get_esc_param(0, 1));
    case 'D': return incr_coord(&vt_state.x, SCREEN_WIDTH, -(int)get_esc_param(0, 1));
    case 'E': vt_state.x = 0; return incr_coord(&vt_state.y, base_height, get_esc_param(0, 1));
    case 'F': vt_state.x = 0; return incr_coord(&vt_state.y, base_height, -(int)get_esc_param(0, 1));
    case 'f':
    case 'H':
        vt_state.y = clamp(get_esc_param(0, 1), 1, base_height) - 1;
        vt_state.x = clamp(get_esc_param(1, 0), 1, SCREEN_WIDTH) - 1;
        return;
    case '`':
    case 'G': vt_state.x = clamp(get_esc_param(0, 1), 1, SCREEN_WIDTH) - 1; return;
    case 'J': return erase_screen(get_esc_param(0, 0));
    case 'K': return erase_line(get_esc_param(0, 0));
    case 'L': return insert_lines(get_esc_param(0, 1));
    case 'M': return delete_lines(get_esc_param(0, 1));
    case 'P': return delete_chars(get_esc_param(0, 1));
    case 'X': return erase_chars(get_esc_param(0, 1));
    case 'c': return inject_id();
    case 'd': vt_state.y = clamp(get_esc_param(0, 1), 1, base_height) - 1; return;
    case 'g': return remove_tab_stops(get_esc_param(0, 0));
    case 'h': return update_mode(mode | get_mode_mask());
    case 'l': return update_mode(mode & ~get_mode_mask());
    case 'm': return set_attributes();
    case 'n': return report_info(get_esc_param(0, 0));
    case 'q': return set_leds(get_esc_param(0, 0));
    case 'r':
        return set_scroll_region(
                clamp(get_esc_param(0, 1), 1, SCREEN_HEIGHT) - 1,
                clamp(get_esc_param(1, SCREEN_HEIGHT), 1, SCREEN_HEIGHT) - 1
        );
    case 's': return save_state();
    case 'u': return restore_state();
    case ']': return process_linux_command(get_esc_param(0, 0));
    default: INVALID_ESCAPE(cp); break;
    }
}

static unsigned get_dec_mode_mask() {
    unsigned mask = 0;

    for (unsigned i = 0; i < esc_nparam; i++) {
        unsigned param = get_esc_param(i, 0);

        switch (param) {
        case 1: mask |= MODE_CURSOR_APPLICATION; break;
        case 5: mask |= MODE_REVERSE_VIDEO; break;
        case 6: mask |= MODE_SCROLL_RELATIVE; break;
        case 7: mask |= MODE_AUTO_WRAP; break;
        case 8: mask |= MODE_AUTO_REPEAT; break;
        case 25: mask |= MODE_CURSOR_VISIBLE; break;
        default: INVALID_PARAM(param); break;
        }
    }

    return mask;
}

static void set_cursor_type() {
    // Changing the cursor type is not supported
    // For future reference:
    //  If parameter 0 is 0, reset to default
    //  Otherwise:
    //   Parameter 0 specifies size:
    //    1: no cursor
    //    2: underline
    //    3: lower 1/3rd
    //    4: lower half
    //    5: lower 2/3rds
    //    6: full block
    //   Parameter 1 specifies which bits should be flipped from the original character
    //   Parameter 2 specifies which bits should be set from the original character
}

static void process_esc_csi_dec(uint32_t cp) {
    esc_state = ESC_NONE;

    switch (cp) {
    case 'c': return set_cursor_type();
    case 'h': return update_mode(mode | get_dec_mode_mask());
    case 'l': return update_mode(mode & ~get_dec_mode_mask());
    case 'n': return report_info(get_esc_param(0, 0));
    default: INVALID_ESCAPE(cp); break;
    }
}

static void process_esc_ignore_one(uint32_t) {
    esc_state = ESC_NONE;
}

static void process_escape(uint32_t cp) {
    switch (esc_state) {
    case ESC_NONE: UNREACHABLE();
    case ESC_INIT: return process_esc_init(cp);
    case ESC_SET_CHARSET: return process_esc_set_charset(cp);
    case ESC_ALIGN_TEST: return process_esc_align_test(cp);
    case ESC_SET_G0: return process_esc_set_g(0, cp);
    case ESC_SET_G1: return process_esc_set_g(1, cp);
    case ESC_OSC: return process_esc_osc(cp);
    case ESC_OSC_PALETTE: return process_esc_osc_palette(cp);
    case ESC_PARAM_IGNORE: return process_esc_param_ignore(cp);
    case ESC_GET_PARAMS: return process_esc_get_params(cp);
    case ESC_CSI_START: return process_esc_csi_start(cp);
    case ESC_CSI: return process_esc_csi(cp);
    case ESC_CSI_DEC: return process_esc_csi_dec(cp);
    case ESC_IGNORE_ONE: return process_esc_ignore_one(cp);
    default:
        esc_state = ESC_NONE;
        INVALID_ESCAPE(cp);
        return;
    }
}

static void do_write_cp(uint32_t cp) {
    // Check for control codes
    switch (cp) {
    case 0: return;
    case 0x07: return; // TODO: Beep
    case 0x08:
        if (vt_state.x > 0) vt_state.x -= 1;
        return;
    case 0x09: {
        vt_state.x++; /* if already at a tab stop, skip it */
        unsigned idx = vt_state.x / 32;
        unsigned off = vt_state.x % 32;

        for (; idx < sizeof(tab_stops) / sizeof(*tab_stops); idx++, off = 0) {
            unsigned j = __builtin_ffs(tab_stops[idx] >> off);

            if (j) {
                vt_state.x = idx * 32 + off + (j - 1);
                return;
            }
        }

        vt_state.x = SCREEN_WIDTH - 1;
        return;
    }
    case 0x0a:
    case 0x0b:
    case 0x0c: emit_lf(); return;
    case 0x0d: vt_state.x = 0; return;
    case 0x0e: return; // TODO: Activate charset G1
    case 0x0f: return; // TODO: Activate charset G0
    case 0x18:
    case 0x1a: esc_state = ESC_NONE; return;
    case 0x1b: esc_state = ESC_INIT; return;
    case 0x7f: return;
    case 0x9b: esc_state = ESC_CSI_START; return;
    }

    if (esc_state != ESC_NONE) {
        process_escape(cp);
        return;
    }

    if (cp < 0x20) {
        INVALID_ESCAPE(cp);
        return;
    }

    set_new_char(vt_state.x++, vt_state.y + base_y, cp_to_val(cp));

    if (vt_state.x >= SCREEN_WIDTH) {
        if (mode & MODE_AUTO_WRAP) {
            vt_state.x = 0;
            vt_state.y += 1;
            maybe_scroll();
        } else {
            vt_state.x = SCREEN_WIDTH - 1;
        }
    }
}

static void update_cursor() {
    screen_set_cursor_enabled(mode & MODE_CURSOR_VISIBLE);
    screen_set_cursor_pos(vt_state.x, vt_state.y + base_y);
}

static void write_code_point(uint32_t cp) {
    do_write_cp(cp);
    update_cursor();
}

static void do_vt_reset() {
    mode = DEFAULT_MODE;
    vt_state.x = vt_state.y = 0;
    vt_state.attributes = DEFAULT_ATTR;
    vt_state.reverse_colors = false;
    base_y = scroll_y0 = 0;
    base_height = scroll_y1 = SCREEN_HEIGHT;
    update_cursor();
    update_autorepeat();

    memset(tab_stops, 0, sizeof(tab_stops));

    for (int i = 0; i < SCREEN_WIDTH; i += 8) {
        set_tab_stop(i);
    }
}

void vt_init() {
    regs_t regs = {.eax = 0xc000};
    intcall(0x15, &regs);

    if (!(regs.eflags & 1)) {
        uint32_t fb2_phys = ((uint32_t)regs.es << 4) + (regs.ebx & 0xffff) + 6;
        uint32_t pgoff = fb2_phys & PAGE_MASK;
        char *ptr = pmap_tmpmap(fb2_phys - pgoff) + pgoff;

        if (*ptr & (1 << 6)) {
            regs = (regs_t){.eax = 0x900};
            intcall(0x16, &regs);

            have_repeat_control = (regs.eax & 3) == 3;
        }
    }

    screen_init();
    do_vt_reset();
    saved_state = vt_state;
}

void vt_reset() {
    screen_reset();
    do_vt_reset();
}

static uint32_t utf8_cur;
static uint32_t utf8_min;
static unsigned utf8_rem;

#define UTF8_ERROR 0xfffd

void vt_write_byte(uint8_t value) {
again:
    if (!utf8_rem) {
        if ((value & 0x80) == 0) {
            write_code_point(value);
            return;
        } else if ((value & 0xe0) == 0xc0) {
            utf8_cur = value & 0x3f;
            utf8_min = 0x80;
            utf8_rem = 1;
        } else if ((value & 0xf0) == 0xe0) {
            utf8_cur = value & 0x1f;
            utf8_min = 0x800;
            utf8_rem = 2;
        } else if ((value & 0xf8) == 0xf0) {
            utf8_cur = value & 0x0f;
            utf8_min = 0x10000;
            utf8_rem = 3;
        } else {
            write_code_point(UTF8_ERROR);
            return;
        }

        return;
    }

    if ((value & 0xc0) != 0x80) {
        write_code_point(UTF8_ERROR);
        utf8_rem = 0;
        goto again;
    }

    utf8_cur <<= 6;
    utf8_cur |= value & 0x3f;

    if (--utf8_rem == 0) {
        write_code_point(utf8_cur >= utf8_min ? utf8_cur : UTF8_ERROR);
    }
}

static uint8_t *injected_input_start;
static uint8_t *injected_input;
static size_t injected_input_cap;
static size_t injected_input_cnt;

static void inject_input(const void *data, size_t count) {
    size_t new_count = injected_input_cnt + count;
    size_t needed_cap = (injected_input - injected_input_start) + new_count;

    if (needed_cap > injected_input_cap) {
        if (new_count > injected_input_cap) {
            void *new_buf = vmalloc(new_count);
            memcpy(new_buf, injected_input, injected_input_cnt);
            vmfree(injected_input_start, injected_input_cap);
            injected_input_start = new_buf;
            injected_input_cap = new_count;
        } else {
            memmove(injected_input_start, injected_input, injected_input_cnt);
        }

        injected_input = injected_input_start;
    }

    memcpy(&injected_input[injected_input_cnt], data, count);
    injected_input_cnt = new_count;
}

static bool pop_injected(uint8_t *out) {
    if (injected_input_cnt) {
        *out = *injected_input++;
        injected_input_cnt--;
        return true;
    }

    return false;
}

static uint8_t process_letter(uint16_t key) {
    uint8_t value = 'a' + KVAL(key);
    if (key & KF_SHIFT) value -= 0x20;
    if (key & KF_CONTROL) value &= ~0x60;

    if (key & KF_ALT) {
        inject_input(&value, 1);
        return 0x1b;
    }

    return value;
}

static uint8_t process_digit(uint16_t key) {
    uint8_t value;

    if (key & KF_SHIFT) value = ")!@#$%^&*("[KVAL(key)];
    else value = '0' + KVAL(key);

    if (key & KF_CONTROL) {
        if (value == '0' || value == '@') value = 0;
        else if (value == '3') value = 0x1b;
        else if (value == '4') value = 0x1c;
        else if (value == '5') value = 0x1d;
        else if (value == '6') value = 0x1e;
        else if (value == '7') value = 0x1f;
        else if (value == '8') value = 0x7f;
        else return 0xff;
    }

    if (key & KF_ALT) {
        if (value == 0x1b || value == 0x1d || value == 0x1e) return 0xff;
        inject_input(&value, 1);
        return 0x1b;
    }

    return value;
}

static uint8_t process_symbol(uint16_t key) {
    uint8_t value;

    if (key & KF_SHIFT) value = " \"<_>?:+{|}~"[KVAL(key)];
    else value = " ',-./;=[\\]`"[KVAL(key)];

    if (key & KF_CONTROL) {
        if (value == ' ') {
            if (key & KF_SHIFT) goto after_control;
            value = 0;
        } else if (value == '`') value = 0;
        else if (value == '\'') value = 7;
        else if (value == '-' || value == '/' || value == '_') value = 0x1f;
        else if (value == '[') value = 0x1b;
        else if (value == '\\') value = 0x1c;
        else if (value == ']') value = 0x1d;
        else if (value == '?') value = 0x7f;
        else return 0xff;
    }
after_control:

    if (key & KF_ALT) {
        if ((key & (KF_CONTROL | KF_SHIFT)) == (KF_CONTROL | KF_SHIFT)) return 0xff;
        if (value == 7 || value == 0x1b || value == 0x1c || value == 0x7f) return 0xff;
        if (value != 0x20 || !(key & KF_SHIFT)) inject_input(&value, 1);
        return 0x1b;
    }

    return value;
}

static uint8_t process_numpad(uint16_t key) {
    if (KVAL(key) >= 11) return "\r*+-/"[KVAL(key) - 11];
    if ((key & (KF_CONTROL | KF_SHIFT | KF_ALT)) == KF_ALT) return 0xff;
    if (key & KF_NUM_LOCK) return "0123456789\r.*+-/"[KVAL(key)];

    if (!(key & KF_SHIFT) && (mode & MODE_KEYPAD_APPLICATION)) {
        switch (key & 0xfff) {
        case K_NUM_0: inject_input("Op", 2); return 0x1b;
        case K_NUM_1: inject_input("Oq", 2); return 0x1b;
        case K_NUM_2: inject_input("Or", 2); return 0x1b;
        case K_NUM_3: inject_input("Os", 2); return 0x1b;
        case K_NUM_4: inject_input("Ot", 2); return 0x1b;
        case K_NUM_5: inject_input("Ou", 2); return 0x1b;
        case K_NUM_6: inject_input("Ov", 2); return 0x1b;
        case K_NUM_7: inject_input("Ow", 2); return 0x1b;
        case K_NUM_8: inject_input("Ox", 2); return 0x1b;
        case K_NUM_9: inject_input("Oy", 2); return 0x1b;
        case K_NUM_DOT: inject_input("On", 2); return 0x1b;
        default: UNREACHABLE();
        }
    }

    switch (key & 0xfff) {
    case K_NUM_0: inject_input("[2~", 3); return 0x1b;
    case K_NUM_1: inject_input("[4~", 3); return 0x1b;
    case K_NUM_2: inject_input("[B", 2); return 0x1b;
    case K_NUM_3: inject_input("[6~", 3); return 0x1b;
    case K_NUM_4: inject_input("[D", 2); return 0x1b;
    case K_NUM_5: inject_input("[G", 2); return 0x1b;
    case K_NUM_6: inject_input("[C", 2); return 0x1b;
    case K_NUM_7: inject_input("[1~", 3); return 0x1b;
    case K_NUM_8: inject_input("[A", 2); return 0x1b;
    case K_NUM_9: inject_input("[5~", 3); return 0x1b;
    case K_NUM_DOT: inject_input("[3~", 3); return 0x1b;
    default: UNREACHABLE();
    }
}

static uint8_t process_arrow(uint16_t key) {
    unsigned char buf[2];
    buf[0] = (mode & MODE_CURSOR_APPLICATION) ? 'O' : '[';
    buf[1] = 'A' + KVAL(key);
    inject_input(buf, sizeof(buf));
    return 0x1b;
}

static uint8_t process_function(uint16_t key) {
    if (key & (KF_CONTROL | KF_ALT)) return 0xff;

    if (key & KF_SHIFT) {
        switch (key & 0xfff) {
        case K_F1: inject_input("[25~", 4); return 0x1b;
        case K_F2: inject_input("[26~", 4); return 0x1b;
        case K_F3: inject_input("[28~", 4); return 0x1b;
        case K_F4: inject_input("[29~", 4); return 0x1b;
        case K_F5: inject_input("[31~", 4); return 0x1b;
        case K_F6: inject_input("[32~", 4); return 0x1b;
        case K_F7: inject_input("[33~", 4); return 0x1b;
        case K_F8: inject_input("[34~", 4); return 0x1b;
        default: return 0xff;
        }
    }

    switch (KVAL(key)) {
    case K_F1: inject_input("[[A", 3); return 0x1b;
    case K_F2: inject_input("[[B", 3); return 0x1b;
    case K_F3: inject_input("[[C", 3); return 0x1b;
    case K_F4: inject_input("[[D", 3); return 0x1b;
    case K_F5: inject_input("[[E", 3); return 0x1b;
    case K_F6: inject_input("[17~", 4); return 0x1b;
    case K_F7: inject_input("[18~", 4); return 0x1b;
    case K_F8: inject_input("[19~", 4); return 0x1b;
    case K_F9: inject_input("[20~", 4); return 0x1b;
    case K_F10: inject_input("[21~", 4); return 0x1b;
    case K_F11: inject_input("[23~", 4); return 0x1b;
    case K_F12: inject_input("[24~", 4); return 0x1b;
    default: UNREACHABLE();
    }
}

static uint8_t process_control(uint16_t key) {
    unsigned mods = key & (KF_CONTROL | KF_SHIFT | KF_ALT);
    if (mods == (KF_CONTROL | KF_SHIFT | KF_ALT)) return 0xff;

    switch (key & 0xfff) {
    case K_ESCAPE: return 0x1b;
    case K_PRINT:
        if (mods & KF_CONTROL) {
            inject_input("\x1c", 1);
            return 0x1b;
        } else if (mods & KF_ALT) {
            return 0x1c;
        }

        return 0xff;
    case K_PAUSE: inject_input("[P", 2); return 0x1b;
    case K_INSERT: inject_input("[2~", 3); return 0x1b;
    case K_DELETE: inject_input("[3~", 3); return 0x1b;
    case K_BACKSPACE:
        if (mods & KF_ALT) {
            inject_input("\x7f", 1);
            return 0x1b;
        }
        return 0x7f;
    case K_HOME: inject_input("[1~", 3); return 0x1b;
    case K_END: inject_input("[4~", 3); return 0x1b;
    case K_PAGE_UP: inject_input("[5~", 3); return 0x1b;
    case K_PAGE_DOWN: inject_input("[6~", 3); return 0x1b;
    case K_TAB:
        if (((mods & KF_ALT) && !(mods & KF_SHIFT)) || (!(mods & KF_ALT) && (mods & KF_SHIFT))) {
            inject_input("\t", 1);
            return 0x1b;
        }
        return '\t';
    case K_ENTER:
        if (mods & KF_ALT) {
            inject_input("\r", 1);
            return 0x1b;
        }

        if (mode & MODE_AUTO_CR) inject_input("\n", 1);
        return '\r';
    default: UNREACHABLE();
    }
}

static uint8_t process_keypress(uint16_t key) {
    switch (KCAT(key)) {
    case KC_LETTER: return process_letter(key);
    case KC_DIGIT: return process_digit(key);
    case KC_SYMBOL: return process_symbol(key);
    case KC_NUMPAD: return process_numpad(key);
    case KC_ARROW: return process_arrow(key);
    case KC_FUNCTION: return process_function(key);
    case KC_CONTROL: return process_control(key);
    default: UNREACHABLE();
    }
}

bool vt_read_byte(uint8_t *out) {
    if (pop_injected(out)) return true;

    uint16_t key = keyboard_read();
    if (!key) return false;

    uint8_t value = process_keypress(key);
    if (value == 0xff) return false;

    *out = value;
    return true;
}

void vt_backspace() {
    if (vt_state.x > 0) {
        vt_state.x -= 1;
    } else {
        ASSERT(vt_state.y > 0);
        vt_state.x = SCREEN_WIDTH - 1;
        vt_state.y -= 1;
    }

    screen_set_char(vt_state.x, vt_state.y + base_y, cp_to_val(BLANK_CHAR));
    update_cursor();
}
