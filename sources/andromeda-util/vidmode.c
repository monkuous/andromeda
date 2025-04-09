#include <andromeda/video.h>
#include <fcntl.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
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

int main(int argc, char *argv[]) {
    progname = argv[0];

    int c;
    bool test = false;
    long mode = -1;

    while ((c = getopt(argc, argv, "htm:")) != -1) {
        switch (c) {
        case '?': return 2;
        case 'h':
            printf("usage: %s [OPTION...] DEVICE\n"
                   "\n"
                   "options:\n"
                   "  -h        show this help message\n"
                   "  -t        test the selected video mode (requires -m)\n"
                   "  -m MODE   only show video mode information for MODE\n",
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
