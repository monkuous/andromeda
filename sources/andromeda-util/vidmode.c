#include <andromeda/video.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sched.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

static const char *progname;

static andromeda_video_mode_t *get_modes(int fd, long mode, size_t *count_out) {
    andromeda_video_modes_t buffer = {};

    if (mode >= 0) {
        buffer.modes = malloc(sizeof(*buffer.modes));
        buffer.start = mode;
        buffer.capacity = 1;
    }

    int result = ioctl(fd, IOCTL_LIST_MODES, &buffer);
    if (result < 0) {
        fprintf(stderr, "%s: failed to get mode info: %m\n", progname);
        exit(1);
    }

    if ((unsigned)result > buffer.capacity) {
        buffer.capacity = result;
        buffer.modes = malloc(buffer.capacity * sizeof(*buffer.modes));
        result = ioctl(fd, IOCTL_LIST_MODES, &buffer);

        if (result < 0) {
            fprintf(stderr, "%s: failed to get mode info: %m\n", progname);
            exit(1);
        }
    }

    *count_out = (unsigned)result;
    return buffer.modes;
}

static void hsv_to_rgb(double rgb[3], double h, double s, double v) {
    unsigned i = h * 6;
    double f = h * 6 - i;
    double p = v * (1 - s);
    double q = v * (1 - f * s);
    double t = v * (1 - (1 - f) * s);

    switch (i % 6) {
    case 0: rgb[0] = v, rgb[1] = t, rgb[2] = p; break;
    case 1: rgb[0] = q, rgb[1] = v, rgb[2] = p; break;
    case 2: rgb[0] = p, rgb[1] = v, rgb[2] = t; break;
    case 3: rgb[0] = p, rgb[1] = q, rgb[2] = v; break;
    case 4: rgb[0] = t, rgb[1] = p, rgb[2] = v; break;
    case 5: rgb[0] = v, rgb[1] = p, rgb[2] = q; break;
    default: __builtin_unreachable();
    }
}

static void xy_to_rgb(double rgb[3], uint32_t x, uint32_t y, andromeda_video_mode_t *mode, double time) {
    hsv_to_rgb(rgb, (double)x / mode->width, time, (double)(mode->height - y - 1) / (mode->height - 1));
}

static uint8_t xy_to_cga(uint32_t x, uint32_t y, andromeda_video_mode_t *mode, double time) {
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

    double rgb[3];
    xy_to_rgb(rgb, x, y, mode, time);
    int r = rgb[0] * 255;
    int g = rgb[1] * 255;
    int b = rgb[2] * 255;

    int cur = 0;
    unsigned cur_dist = -1;

    for (int i = 0; i < 16; i++) {
        int dr = r - colors[i][0];
        int dg = g - colors[i][1];
        int db = b - colors[i][2];
        unsigned dist = dr * dr + dg * dg + db * db;

        if (dist < cur_dist) {
            cur = i;
            cur_dist = dist;
        }
    }

    return cur;
}

static void set_cga_text(volatile void *addr, andromeda_video_mode_t *mode, double time) {
    if (mode->bits_per_pixel != 16) {
        fprintf(stderr, "%s: cga: unsupported pixel size (%u bits)\n", progname, mode->bits_per_pixel);
        exit(1);
    }

    for (uint32_t y = 0; y < mode->height; y++, addr += mode->pitch) {
        volatile uint16_t *line = addr;

        for (uint32_t x = 0; x < mode->width; x++) {
            *line++ = ((uint16_t)xy_to_cga(x, y, mode, time) << 8) | 0xdb;
        }
    }
}

static uint32_t float_to_mask(double value, unsigned mask_size, unsigned field_pos) {
    return (unsigned)(value * ((1u << mask_size) - 1)) << field_pos;
}

static uint32_t rgb_for_coord(uint32_t x, uint32_t y, andromeda_video_mode_t *mode, double time) {
    double color[3];
    xy_to_rgb(color, x, y, mode, time);

    uint32_t value = 0;
    value |= float_to_mask(color[0], mode->rgb.red.mask_size, mode->rgb.red.field_pos);
    value |= float_to_mask(color[1], mode->rgb.green.mask_size, mode->rgb.green.field_pos);
    value |= float_to_mask(color[2], mode->rgb.blue.mask_size, mode->rgb.blue.field_pos);
    return value;
}

static void set_rgb16(volatile void *addr, andromeda_video_mode_t *mode, double time) {
    for (uint32_t y = 0; y < mode->height; y++, addr += mode->pitch) {
        volatile uint16_t *line = addr;

        for (uint32_t x = 0; x < mode->width; x++) {
            *line++ = rgb_for_coord(x, y, mode, time);
        }
    }
}

static void set_rgb24(volatile void *addr, andromeda_video_mode_t *mode, double time) {
    for (uint32_t y = 0; y < mode->height; y++, addr += mode->pitch) {
        volatile uint8_t *line = addr;

        for (uint32_t x = 0; x < mode->width; x++) {
            uint32_t value = rgb_for_coord(x, y, mode, time);
            *line++ = value;
            *line++ = value >> 8;
            *line++ = value >> 16;
        }
    }
}

static void set_rgb32(volatile void *addr, andromeda_video_mode_t *mode, double time) {
    for (uint32_t y = 0; y < mode->height; y++, addr += mode->pitch) {
        volatile uint32_t *line = addr;

        for (uint32_t x = 0; x < mode->width; x++) {
            *line++ = rgb_for_coord(x, y, mode, time);
        }
    }
}

static void set_rgb(volatile void *addr, andromeda_video_mode_t *mode, double time) {
    switch (mode->bits_per_pixel) {
    case 15:
    case 16: return set_rgb16(addr, mode, time);
    case 24: return set_rgb24(addr, mode, time);
    case 32: return set_rgb32(addr, mode, time);
    default: fprintf(stderr, "%s: rgb: unsupported pixel size (%u bits)\n", progname, mode->bits_per_pixel); exit(1);
    }
}

static void set_fb(volatile void *addr, andromeda_video_mode_t *mode, double time) {
    switch (mode->memory_model) {
    case ANDROMEDA_MEMORY_MODEL_CGA_TEXT: return set_cga_text(addr, mode, time);
    case ANDROMEDA_MEMORY_MODEL_RGB: return set_rgb(addr, mode, time);
    default: fprintf(stderr, "%s: unknown memory model: %u\n", progname, mode->memory_model); exit(1);
    }
}

static void test_mode(int fd, int index) {
    int memfd = open("/dev/mem", O_RDWR);
    if (memfd < 0) {
        fprintf(stderr, "%s: failed to open /dev/mem: %m\n", progname);
        exit(1);
    }

    andromeda_framebuffer_request_t request = {.mode_index = index};
    int result = ioctl(fd, IOCTL_SET_MODE, &request);
    if (result < 0) {
        fprintf(stderr, "%s: failed to set mode: %m\n", progname);
        exit(1);
    }
    size_t fb_size = (request.framebuffer.mode.pitch * request.framebuffer.mode.height + 0xfff) & ~0xfff;

    void *addr = mmap(NULL, fb_size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, request.framebuffer.address);
    if (addr == MAP_FAILED) {
        fprintf(stderr, "%s: failed to map framebuffer: %m\n", progname);
        exit(1);
    }

    double time = 0;

    for (;;) {
        set_fb(addr, &request.framebuffer.mode, time >= 0 ? time : -time);
        sched_yield();

        time += 0.01;
        if (time > 1.0) time -= 2.0;
    }
}

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
    uint16_t reserved0;
    uint8_t reserved1;
    uint8_t tag;
    union {
        struct [[gnu::packed]] {
            uint8_t reserved;
            uint8_t data[13];
        } string;
        struct [[gnu::packed]] {
            uint8_t flags;
            uint8_t min_vrate;
            uint8_t max_vrate;
            uint8_t min_hrate;
            uint8_t max_hrate;
            uint8_t max_clock;
            uint8_t flags2;
            union {
                struct [[gnu::packed]] {
                    uint8_t start_break_freq;
                    uint8_t c2;
                    uint16_t m;
                    uint8_t k;
                    uint8_t j2;
                } gtf;
                struct [[gnu::packed]] {
                    uint8_t version;
                    uint8_t byte12;
                    uint8_t max_active_per_line_low;
                    uint8_t supported_ars;
                    uint8_t preferred_ar;
                    uint8_t scaling_support;
                    uint8_t pref_vrate;
                } cvt;
            };
        } extra_timings;
        struct [[gnu::packed]] {
            uint8_t reserved;
            struct {
                uint8_t index;
                uint8_t xy_low;
                uint8_t x_high;
                uint8_t y_high;
                uint8_t gamma;
            } data[2];
        } color_point;
        struct [[gnu::packed]] {
            uint8_t reserved;
            uint16_t codes[6];
        } std_timings;
        struct [[gnu::packed]] {
            uint8_t reserved;
            uint8_t version;
            uint16_t codes[6];
        } color_data;
        struct [[gnu::packed]] {
            uint8_t reserved;
            uint8_t version;
            struct {
                uint8_t lines_low;
                uint8_t lines_high_ar;
                uint8_t pref_sup_vrate;
            } descs[3];
        } cvt;
        struct [[gnu::packed]] {
            uint8_t reserved;
            uint8_t revision;
            uint8_t bitmap[6];
        } et3;
    };
} display_desc_t;

typedef union {
    timing_desc_t timing;
    display_desc_t display;
} descriptor_t;

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
    descriptor_t descriptors[3];
    uint8_t extensions;
    uint8_t checksum;
} edid_t;

static void show_timing_desc(timing_desc_t *desc) {
    const char *stereo;

    switch (desc->flags & 0x61) {
    case 0x40: stereo = "field sequential, right during sync"; break;
    case 0x60: stereo = "field sequential, left during sync"; break;
    case 0x41: stereo = "2-way interleaved, right on even"; break;
    case 0x61: stereo = "2-way interleaved, left on even"; break;
    case 0x70: stereo = "4-way interleaved"; break;
    case 0x71: stereo = "side-by-side interleaved"; break;
    default: stereo = "none"; break;
    }

    printf("%ux%u, %u kHz pixel clock, %ux%u blank, %ux%u front porch, %ux%u sync pulse width, %ux%u border, %ux%u mm, "
           "interlaced: %s, stereo: %s, sync: ",
           desc->width_low | ((desc->width_hblank_high & 0xf0) << 4),
           desc->height_low | ((desc->height_vblank_high & 0xf0) << 4),
           desc->pixel_clock * 10,
           desc->hblank_low | ((desc->width_hblank_high & 0x0f) << 8),
           desc->vblank_low | ((desc->height_vblank_high & 0x0f) << 8),
           desc->hporch_low | ((desc->porch_syncw_high & 0xc0) << 2),
           ((desc->vporch_vsyncw_low & 0xf0) >> 4) | ((desc->porch_syncw_high & 0x0c) << 2),
           desc->hsyncw_low | ((desc->porch_syncw_high & 0x30) << 4),
           (desc->vporch_vsyncw_low & 0x0f) | ((desc->porch_syncw_high & 0x03) << 4),
           desc->hborder,
           desc->vborder,
           desc->hsize_low | ((desc->size_high & 0xf0) << 4),
           desc->vsize_low | ((desc->size_high & 0x0f) << 8),
           (desc->flags & 0x80) ? "yes" : "no",
           stereo);

    if ((desc->flags & 0x18) == 0x18) {
        printf("digital separate, vsync %s, hsync %s\n",
               (desc->flags & 0x04) ? "positive" : "negative",
               (desc->flags & 0x02) ? "positive" : "negative");
    } else if (desc->flags & 0x10) {
        printf("digital composite %s serrations, hsync %s\n",
               (desc->flags & 0x04) ? "with" : "without",
               (desc->flags & 0x02) ? "positive" : "negative");
    } else {
        printf("analog %s serrations, bipolar: %s, sync on %s\n",
               (desc->flags & 0x04) ? "with" : "without",
               (desc->flags & 0x08) ? "yes" : "no",
               (desc->flags & 0x02) ? "all signals" : "green");
    }
}

static void show_std_timing(uint16_t value) {
    unsigned width = ((value & 0xff) + 31) * 8;
    unsigned height;
    const char *ar;
    unsigned refresh = ((value >> 8) & 0x3f) + 60;

    switch (value & 0xc000) {
    case 0x0000:
        height = (width * 10) / 16;
        ar = "16:10";
        break;
    case 0x4000:
        height = (width * 3) / 4;
        ar = "4:3";
        break;
    case 0x8000:
        height = (width * 4) / 5;
        ar = "5:4";
        break;
    case 0xc000:
        height = (width * 9) / 16;
        ar = "16:9";
        break;
    default: unreachable(); break;
    }

    printf("%ux%u (%s) @ %u Hz", width, height, ar, refresh);
}

static void show_display_desc(display_desc_t *desc) {
    switch (desc->tag) {
    case 0xff: {
        char *ptr = memchr(desc->string.data, '\n', sizeof(desc->string));
        if (ptr) *ptr = 0;
        printf("Serial number: %s\n", desc->string.data);
        break;
    }
    case 0xfe: {
        char *ptr = memchr(desc->string.data, '\n', sizeof(desc->string));
        if (ptr) *ptr = 0;
        printf("Data string: %s\n", desc->string.data);
        break;
    }
    case 0xfd: {
        unsigned min_vrate = desc->extra_timings.min_vrate;
        unsigned max_vrate = desc->extra_timings.max_vrate;
        unsigned min_hrate = desc->extra_timings.min_hrate;
        unsigned max_hrate = desc->extra_timings.max_hrate;
        if (desc->extra_timings.flags & 1) min_vrate += 255;
        if (desc->extra_timings.flags & 2) max_vrate += 255;
        if (desc->extra_timings.flags & 4) min_hrate += 255;
        if (desc->extra_timings.flags & 8) max_hrate += 255;
        unsigned pixel_clock = desc->extra_timings.max_clock * 10;
        printf("Range limits: horizontal %u-%u kHz, vertical %u-%u Hz, maximum pixel clock ",
               min_hrate,
               max_hrate,
               min_vrate,
               max_vrate);

        if (desc->extra_timings.flags2 == 4) {
            pixel_clock *= 1000;
            pixel_clock -= (desc->extra_timings.cvt.byte12 >> 2) * 250;
            printf("%u kHz", pixel_clock);

            printf(", CVT version: %u.%u", desc->extra_timings.cvt.version >> 4, desc->extra_timings.cvt.version & 15);

            if (desc->extra_timings.cvt.max_active_per_line_low) {
                printf(", max active pixels per line %u",
                       desc->extra_timings.cvt.max_active_per_line_low | ((desc->extra_timings.cvt.byte12 & 3) << 8));
            }

            static const char *ar_names[] = {"4:3", "16:9", "16:10", "5:4", "15:9"};

            {
                bool have_one = false;
                printf(", supported aspect ratios: ");

                for (int i = 0; i < 5; i++) {
                    if (desc->extra_timings.cvt.supported_ars & (1ul << (7 - i))) {
                        if (have_one) {
                            printf(", ");
                        } else {
                            have_one = true;
                        }

                        printf("%s", ar_names[i]);
                    }
                }

                if (!have_one) printf("none");
            }

            printf(", preferred aspect ratio: %s", ar_names[desc->extra_timings.cvt.preferred_ar >> 5]);
            printf(", standard CVT blanking: %s",
                   (desc->extra_timings.cvt.preferred_ar) & 0x08 ? "supported" : "unsupported");
            printf(", reduced CVT blanking: %s",
                   (desc->extra_timings.cvt.preferred_ar) & 0x10 ? "supported" : "unsupported");
            printf(", horizontal shrinking: %s",
                   (desc->extra_timings.cvt.scaling_support & 0x80) ? "supported" : "unsupported");
            printf(", horizontal stretching: %s",
                   (desc->extra_timings.cvt.scaling_support & 0x40) ? "supported" : "unsupported");
            printf(", vertical shrinking: %s",
                   (desc->extra_timings.cvt.scaling_support & 0x20) ? "supported" : "unsupported");
            printf(", vertical stretching: %s",
                   (desc->extra_timings.cvt.scaling_support & 0x10) ? "supported" : "unsupported");
            printf(", preferred refresh rate: %u Hz\n", desc->extra_timings.cvt.pref_vrate);
        } else {
            printf("%u MHz", pixel_clock);

            if (desc->extra_timings.flags2 == 2) {
                printf(", GTF: start break freq = %u kHz, C = %u, M = %u, K = %u, J = %u\n",
                       desc->extra_timings.gtf.start_break_freq * 2,
                       desc->extra_timings.gtf.c2 * 2,
                       desc->extra_timings.gtf.m,
                       desc->extra_timings.gtf.k,
                       desc->extra_timings.gtf.j2 * 2);
            } else {
                putchar('\n');
            }
        }
        break;
    }
    case 0xfc: {
        char *ptr = memchr(desc->string.data, '\n', sizeof(desc->string));
        if (ptr) *ptr = 0;
        printf("Product name: %s\n", desc->string.data);
        break;
    }
    case 0xfb: {
        for (int i = 0; i < 2; i++) {
            if (!desc->color_point.data[i].index) continue;

            printf("White point %u: (%f, %f)",
                   desc->color_point.data[i].index,
                   ((desc->color_point.data[i].x_high << 2) | ((desc->color_point.data[i].xy_low & 0xc) >> 2)) / 1023.0,
                   ((desc->color_point.data[i].y_high << 2) | (desc->color_point.data[i].xy_low & 3)) / 1023.0);

            if (desc->color_point.data[i].gamma == 0xff) {
                printf(", gamma: %f", (desc->color_point.data[i].gamma + 100) / 100.0);
            }

            putchar('\n');
        }
        break;
    }
    case 0xfa: {
        bool have_one = false;
        printf("Additional standard timings: ");

        for (int i = 0; i < 6; i++) {
            if (desc->std_timings.codes[i] != 0x101) {
                if (have_one) printf(", ");
                else have_one = true;

                show_std_timing(desc->std_timings.codes[i]);
            }
        }

        if (have_one) putchar('\n');
        else printf("none\n");
        break;
    }
    case 0xf9: {
        printf("Color management data: ");

        for (int i = 0; i < 6; i++) {
            static const char *names[] = {"red a_3", "red a_2", "green a_3", "green a_2", "blue a_3", "blue a_2"};

            printf("%s = %#.4x", names[i], desc->color_data.codes[i]);
            if (i != 5) printf(", ");
        }

        putchar('\n');
        break;
    }
    case 0xf8: {
        printf("CVT 3-byte codes: ");
        bool have_one = false;

        for (int i = 0; i < 3; i++) {
            if (desc->cvt.descs[i].lines_low) continue;

            unsigned height = ((desc->cvt.descs[i].lines_low | ((desc->cvt.descs[i].lines_high_ar & 0xf0) >> 4)) + 1) *
                              2;
            unsigned pref_vrate = 50 + ((desc->cvt.descs[i].pref_sup_vrate >> 5) & 3);
            if (pref_vrate > 60) pref_vrate += 5;

            if (have_one) printf("; ");
            else have_one = true;

            unsigned width;
            const char *ar;

            switch ((desc->cvt.descs[i].lines_high_ar >> 2) & 3) {
            case 0:
                ar = "4:3";
                width = (height * 4) / 3;
                break;
            case 1:
                ar = "16:9";
                width = (height * 16) / 9;
                break;
            case 2:
                ar = "16:10";
                width = (height * 16) / 10;
                break;
            case 3:
                ar = "15:9";
                width = (height * 15) / 9;
                break;
            default: unreachable();
            }

            width = 8 * (width / 8);
            printf("%ux%u, %s, preferred refresh rate = %u Hz", width, height, ar, pref_vrate);

            if (desc->cvt.descs[i].pref_sup_vrate & 0x10) printf(", supports standard 50 Hz");
            if (desc->cvt.descs[i].pref_sup_vrate & 0x08) printf(", supports standard 60 Hz");
            if (desc->cvt.descs[i].pref_sup_vrate & 0x04) printf(", supports standard 75 Hz");
            if (desc->cvt.descs[i].pref_sup_vrate & 0x02) printf(", supports standard 85 Hz");
            if (desc->cvt.descs[i].pref_sup_vrate & 0x01) printf(", supports reduced 60 Hz");
        }

        if (have_one) putchar('\n');
        else printf("none\n");

        break;
    }
    case 0xf7: {
        printf("Additional timing bitmap: ");
        bool have_one = false;

        for (int i = 0; i < 44; i++) {
            static const char *names[] = {
                    "640x350 @ 85 Hz",
                    "640x400 @ 85 Hz",
                    "720x400 @ 85 Hz",
                    "640x480 @ 85 Hz",
                    "848x480 @ 60 Hz",
                    "800x600 @ 85 Hz",
                    "1024x768 @ 85 Hz",
                    "1152x864 @ 75 Hz",
                    "1280x768 @ 60 Hz (reduced blanking)",
                    "1280x768 @ 60 Hz",
                    "1280x768 @ 75 Hz",
                    "1280 x 768 @ 85 Hz",
                    "1280 x 960 @ 60 Hz",
                    "1280 x 960 @ 85 Hz",
                    "1280 x 1024 @ 60 Hz",
                    "1280 x 1024 @ 85 Hz",
                    "1360 x 768 @ 60 Hz",
                    "1440 x 900 @ 60 Hz (reduced blanking)",
                    "1440 x 900 @ 60 Hz",
                    "1440 x 900 @ 75 Hz",
                    "1440 x 900 @ 85 Hz",
                    "1400 x 1050 @ 60 Hz (reduced blanking)",
                    "1400 x 1050 @ 60 Hz",
                    "1400 x 1050 @ 75 Hz",
                    "1400 x 1050 @ 85 Hz",
                    "1680 x 1050 @ 60 Hz (reduced blanking)",
                    "1680 x 1050 @ 60 Hz",
                    "1680 x 1050 @ 75 Hz",
                    "1680 x 1050 @ 85 Hz",
                    "1600 x 1200 @ 60 Hz",
                    "1600 x 1200 @ 65 Hz",
                    "1600 x 1200 @ 70 Hz",
                    "1600 x 1200 @ 75 Hz",
                    "1600 x 1200 @ 85 Hz",
                    "1792 x 1344 @ 60 Hz",
                    "1792 x 1344 @ 75 Hz",
                    "1856 x 1392 @ 60 Hz",
                    "1856 x 1392 @ 75 Hz",
                    "1920 x 1200 @ 60 Hz (reduced blanking)",
                    "1920 x 1200 @ 60 Hz",
                    "1920 x 1200 @ 75 Hz",
                    "1920 x 1200 @ 85 Hz",
                    "1920 x 1440 @ 60 Hz",
                    "1920 x 1440 @ 75 Hz",
            };

            if (desc->et3.bitmap[i / 8] & (1u << (7 - (i % 8)))) {
                if (have_one) printf(", ");
                else have_one = true;

                printf("%s", names[i]);
            }
        }

        if (have_one) putchar('\n');
        else printf("none\n");
        break;
    }
    }
}

static void show_edid(int fd, bool raw) {
    andromeda_edid_request_t request = {};
    int size = ioctl(fd, IOCTL_GET_EDID, &request);
    if (size < 0) {
        fprintf(stderr, "%s: failed to get edid size: %m\n", progname);
        exit(1);
    }

    request.capacity = size;
    request.buffer = malloc(size);

    if (ioctl(fd, IOCTL_GET_EDID, &request) < 0) {
        fprintf(stderr, "%s: failed to get edid data: %m\n", progname);
        exit(1);
    }

    if (raw) {
        if (fwrite(request.buffer, 1, request.capacity, stdout) != request.capacity) {
            fprintf(stderr, "%s: failed to write edid information: %m\n", progname);
            exit(1);
        }

        return;
    }

    edid_t *edid = request.buffer;

    {
        edid->manufacturer = ntohs(edid->manufacturer);

        char manufacturer[4];
        manufacturer[0] = 0x40 | ((edid->manufacturer >> 10) & 0x1f);
        manufacturer[1] = 0x40 | ((edid->manufacturer >> 5) & 0x1f);
        manufacturer[2] = 0x40 | (edid->manufacturer & 0x1f);
        manufacturer[3] = 0;

        printf("Manufacturer ID: %s\n", manufacturer);
        printf("Product code: %#.4x\n", edid->product_code);
        printf("Serial number: %#.8x\n", edid->serial_number);
    }

    {
        if (edid->manufacture_week && edid->manufacture_week != 0xff) {
            printf("Week of manufacture: %d\n", edid->manufacture_week);
        }

        int year = edid->manufacture_year + 1990;

        if (edid->manufacture_week != 0xff) printf("Year of manufacture: %d\n", year);
        else printf("Model year: %d\n", year);
    }

    printf("EDID version: %d.%d\n", edid->edid_version, edid->edid_revision);

    if (edid->input_definition & 0x80) {
        // Digital
        const char *depth;

        switch (edid->input_definition & 0x70) {
        case 0x10: depth = "6 bit"; break;
        case 0x20: depth = "8 bit"; break;
        case 0x30: depth = "10 bit"; break;
        case 0x40: depth = "12 bit"; break;
        case 0x50: depth = "14 bit"; break;
        case 0x60: depth = "16 bit"; break;
        default: depth = "unknown"; break;
        }

        const char *interface;

        switch (edid->input_definition & 0x0f) {
        case 0x01: interface = "DVI"; break;
        case 0x02: interface = "HDMI-a"; break;
        case 0x03: interface = "HDMI-b"; break;
        case 0x04: interface = "MDDI"; break;
        case 0x05: interface = "DisplayPort"; break;
        default: interface = "unknown interface"; break;
        }

        printf("Input: digital, %s color depth, %s\n", depth, interface);
    } else {
        // Analog
        const char *signal_level;

        switch (edid->input_definition & 0x60) {
        case 0x00: signal_level = "0.700 : 0.300 : 1.000 V p-p"; break;
        case 0x20: signal_level = "0.714 : 0.286 : 1.000 V p-p"; break;
        case 0x40: signal_level = "1.000 : 0.400 : 1.400 V p-p"; break;
        case 0x60: signal_level = "0.700 : 0.000 : 0.700 V p-p"; break;
        default: unreachable();
        }

        printf("Input: analog, %s, %s, separate sync %s, composite sync %s, composite sync on green %s, serration "
               "%s\n",
               signal_level,
               (edid->input_definition & 0x10) ? "blank-to-black" : "blank = black",
               (edid->input_definition & 0x08) ? "supported" : "unsupported",
               (edid->input_definition & 0x04) ? "supported" : "unsupported",
               (edid->input_definition & 0x02) ? "supported" : "unsupported",
               (edid->input_definition & 0x01) ? "supported" : "unsupported");
    }

    if (edid->max_vert_size) {
        if (edid->max_horiz_size) {
            printf("Maximum horizontal size: %d cm\n", edid->max_horiz_size);
            printf("Maximum vertical size: %d cm\n", edid->max_vert_size);
        } else {
            printf("Aspect ratio: portrait, %f\n", 100.0 / (edid->max_vert_size + 99));
        }
    } else if (edid->max_horiz_size) {
        printf("Aspect ratio: landscape, %f\n", (edid->max_horiz_size + 99) / 100.0);
    }

    if (edid->gamma != 0xff) {
        printf("Gamma: %f\n", (edid->gamma + 100) / 100.0);
    }

    printf("DPMS Standby: %s\n", (edid->features & 0x80) ? "supported" : "unsupported");
    printf("DPMS Suspend: %s\n", (edid->features & 0x40) ? "supported" : "unsupported");
    printf("DPMS Active-Off: %s\n", (edid->features & 0x20) ? "supported" : "unsupported");

    if (edid->input_definition & 0x80) {
        switch (edid->features & 0x18) {
        case 0x00: printf("Supported color encoding formats: RGB 4:4:4\n"); break;
        case 0x08: printf("Supported color encoding formats: RGB 4:4:4, YCrCb 4:4:4\n"); break;
        case 0x10: printf("Supported color encoding formats: RGB 4:4:4, YCrCb 4:2:2\n"); break;
        case 0x18: printf("Supported color encoding formats: RGB 4:4:4, YCrCb 4:4:4, YCrCb 4:2:2\n"); break;
        }
    } else {
        switch (edid->features & 0x18) {
        case 0x00: printf("Color type: Monochrome\n"); break;
        case 0x08: printf("Color type: RGB color\n"); break;
        case 0x10: printf("Color type: Non-RGB color\n"); break;
        case 0x18: printf("Color type: unknown\n"); break;
        }
    }

    printf("Default color space is sRGB: %s\n", (edid->features & 0x04) ? "yes" : "no");
    printf("Preferred timing mode lists preferred pixel format and refresh rate: %s\n",
           (edid->features & 0x02) ? "yes" : "no");
    printf("GTF: %s\n", (edid->features & 0x01) ? "supported" : "unsupported");
    printf("Chromaticity coordinates:\n");

    for (int i = 0; i < 4; i++) {
        static const char *names[] = {"Red", "Green", "Blue", "White"};
        printf(" %s: (", names[i]);

        for (int j = 0; j < 2; j++) {
            unsigned idx = i * 2 + j;
            unsigned value = edid->chroma[2 + idx] << 2;
            value |= (edid->chroma[idx / 4] >> (6 - idx % 4)) & 3;
            printf("%f%s", value / 1023.0, (j & 1) ? ")" : ", ");
        }

        putchar('\n');
    }

    {
        static const char *timings[] = {
                "720x400 @ 70 Hz",
                "720x400 @ 88 Hz",
                "640x480 @ 60 Hz",
                "640x480 @ 67 Hz",
                "640x480 @ 72 Hz",
                "640x480 @ 75 Hz",
                "800x600 @ 56 Hz",
                "800x600 @ 60 Hz",
                "800x600 @ 72 Hz",
                "800x600 @ 75 Hz",
                "832x624 @ 75 Hz",
                "1024x768 @ 87 Hz (interlaced)",
                "1024x768 @ 60 Hz",
                "1024x768 @ 70 Hz",
                "1024x768 @ 75 Hz",
                "1280x1024 @ 75 Hz",
                "1152x870 @ 75 Hz",
        };

        bool have_one = false;

        printf("Timing bitmap: ");

        for (int i = 0; i < 17; i++) {
            if (edid->timing_bitmap[i / 8] & (1 << (7 - (i % 8)))) {
                if (have_one) {
                    printf(", ");
                } else {
                    have_one = true;
                }

                printf("%s", timings[i]);
            }
        }

        if (!have_one) printf("none\n");
        else putchar('\n');
    }

    {
        bool have_one = false;
        printf("Standard timings: ");

        for (int i = 0; i < 8; i++) {
            uint16_t value = edid->std_timings[i];

            if (value != 0x101) {
                if (have_one) {
                    printf(", ");
                } else {
                    have_one = true;
                }

                show_std_timing(value);
            }
        }

        if (have_one) putchar('\n');
        else printf("none\n");
    }

    printf("Preferred timing: ");
    show_timing_desc(&edid->pref_timing);

    for (int i = 0; i < 3; i++) {
        descriptor_t *desc = &edid->descriptors[i];

        if (desc->timing.pixel_clock) {
            printf("Timing: ");
            show_timing_desc(&desc->timing);
        } else {
            show_display_desc(&desc->display);
        }
    }
}

int main(int argc, char *argv[]) {
    progname = argv[0];

    int c;
    bool test = false;
    long mode = -1;
    bool edid = false;
    bool edid_raw = false;

    while ((c = getopt(argc, argv, "htm:eE")) != -1) {
        switch (c) {
        case '?': return 2;
        case 'h':
            printf("usage: %s [OPTION...] DEVICE\n"
                   "\n"
                   "options:\n"
                   "  -h        show this help message\n"
                   "  -t        test the selected video mode (requires -m)\n"
                   "  -m MODE   only show video mode information for MODE\n"
                   "  -e        show edid information\n"
                   "  -E        write raw edid information to standard output\n",
                   progname);
            return 0;
        case 't': test = true; break;
        case 'm': {
            char *end;
            mode = strtol(optarg, &end, 10);
            if (*end || mode < 0) {
                fprintf(stderr, "%s: invalid mode number %s\n", argv[0], optarg);
                return 2;
            }
            break;
        }
        case 'e': edid = true; break;
        case 'E':
            edid = true;
            edid_raw = true;
            break;
        }
    }

    if (test && mode < 0) {
        fprintf(stderr, "%s: -t requires -m\n", argv[0]);
        return 2;
    }

    if (optind >= argc) {
        fprintf(stderr, "usage: %s [OPTION...] DEVICE\n", argv[0]);
        return 2;
    }

    const char *device_path = argv[optind];
    int fd = open(device_path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: failed to open %s: %m\n", argv[0], device_path);
        return 1;
    }

    if (test) {
        test_mode(fd, mode);
        return 0;
    }

    if (edid) {
        show_edid(fd, edid_raw);
        return 0;
    }

    size_t count;
    andromeda_video_mode_t *modes = get_modes(fd, mode, &count);

    if (!count) {
        fprintf(stderr, "%s: no video modes found\n", argv[0]);
        return 1;
    }

    for (size_t i = 0; i < count; i++) {
        const char *model;

        switch (modes[i].memory_model) {
        case ANDROMEDA_MEMORY_MODEL_CGA_TEXT: model = "CGA text"; break;
        case ANDROMEDA_MEMORY_MODEL_RGB: model = "RGB"; break;
        default: model = "unknown memory model";
        }

        printf("Mode %u: %ux%u (%s, %u bits per pixel, %llu bytes per line)\n",
               i,
               modes[i].width,
               modes[i].height,
               model,
               modes[i].bits_per_pixel,
               modes[i].pitch);

        if (modes[i].memory_model == ANDROMEDA_MEMORY_MODEL_RGB) {
            printf(" RGB component masks: %#.8x, %#.8x, %#.8x\n",
                   ((1u << modes[i].rgb.red.mask_size) - 1) << modes[i].rgb.red.field_pos,
                   ((1u << modes[i].rgb.green.mask_size) - 1) << modes[i].rgb.green.field_pos,
                   ((1u << modes[i].rgb.blue.mask_size) - 1) << modes[i].rgb.blue.field_pos);
        }
    }
}
