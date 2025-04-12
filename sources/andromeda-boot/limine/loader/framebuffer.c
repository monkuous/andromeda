#include "framebuffer.h"
#include "libboot.h"
#include "limine.h"
#include "main.h"
#include "memory.h"
#include "requests.h"
#include "util.h"
#include "utils.h"
#include <andromeda/video.h>
#include <stdio.h>
#include <stdlib.h>

void init_framebuffer() {
    struct limine_framebuffer_request *request = get_request(REQUEST_FRAMEBUFFER);
    if (!request) return;

    struct limine_framebuffer *framebuffers = nullptr;
    size_t count = 0;

    if (!libboot_video_init(0)) {
        fprintf(stderr, "%s: failed to initialize video: %m\n", progname);
        exit(1);
    }

    size_t cards = libboot_video_num_cards();

    for (size_t i = 0; i < cards; i++) {
        libboot_video_card_t *card = libboot_video_get_card(i);
        ssize_t nmodes = libboot_video_discover_modes(card);
        if (nmodes < 0) {
            fprintf(stderr, "%s: failed to get video mode list: %m\n", progname);
            exit(1);
        }
        if (nmodes == 0) continue;

        ssize_t mode = libboot_video_pick_mode(card, user_width, user_height);
        if (mode < 0) {
            if (errno == ENODATA) continue;
            fprintf(stderr, "%s: failed to pick video mode: %m\n", progname);
            exit(1);
        }

        andromeda_framebuffer_t fb;
        int fd = libboot_video_set_mode(card, &fb, mode);
        if (fd < 0) {
            fprintf(stderr, "%s: failed to set video mode: %m\n", progname);
            exit(1);
        }

        struct limine_framebuffer lfb = {
                .address = boot_info.responses.hhdm.offset + fb.address,
                .width = fb.mode.width,
                .height = fb.mode.height,
                .pitch = fb.mode.pitch,
                .bpp = fb.mode.bits_per_pixel,
        };

        switch (fb.mode.memory_model) {
        case ANDROMEDA_MEMORY_MODEL_RGB:
            lfb.memory_model = LIMINE_FRAMEBUFFER_RGB;
            lfb.red_mask_size = fb.mode.rgb.red.mask_size;
            lfb.red_mask_shift = fb.mode.rgb.red.field_pos;
            lfb.green_mask_size = fb.mode.rgb.green.mask_size;
            lfb.green_mask_shift = fb.mode.rgb.green.field_pos;
            lfb.blue_mask_size = fb.mode.rgb.blue.mask_size;
            lfb.blue_mask_shift = fb.mode.rgb.blue.field_pos;
            break;
        default: close(fd); continue;
        }

        size_t edid_size;
        const void *edid = libboot_video_get_edid_data(card, &edid_size);
        if (edid) {
            lfb.edid_size = edid_size;
            paddr_t addr = UINT64_MAX;
            void *ptr = alloc_pages(&addr, edid_size, 1, LIMINE_MEMORY_LOADER);
            memcpy(ptr, edid, edid_size);
            lfb.edid = boot_info.responses.hhdm.offset + addr;
        }

        libboot_mem_set_type(fb.address, fb.address + fb.mode.pitch * fb.mode.height - 1, LIMINE_MEMORY_FRAMEBUFFER);

        size_t idx = count++;
        framebuffers = realloc(framebuffers, count * sizeof(*framebuffers));
        framebuffers[idx] = lfb;
    }

    boot_info.responses.framebuffer.framebuffers = create_pointer_array(framebuffers, sizeof(*framebuffers), count);
    boot_info.responses.framebuffer.framebuffer_count = count;
}
