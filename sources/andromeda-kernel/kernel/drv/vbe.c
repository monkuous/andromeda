#include "vbe.h"
#include "compiler.h"
#include "drv/console/screen.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/layout.h"
#include "mem/pmap.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "string.h"
#include "sys/syscall.h"
#include "util/panic.h"
#include "util/print.h"
#include <abi-bits/fcntl.h>
#include <andromeda/video.h>
#include <errno.h>
#include <stdint.h>

#define VBE_SUCCESS(x) (((x) & 0xffff) == 0x4f)
#define VBE_SUPPORTED(x) (((x) & 0xff) == 0x4f)
#define VBE_STATUS(x) ((x) & 0xffff)

#define VBE_1_2 0x0102
#define VBE_2_0 0x0200
#define VBE_3_0 0x0300

#define VBE_MIN_VERSION VBE_1_2

#define VBE_MODE_SUPPORTED 1
#define VBE_MODE_GRAPHICS 16
#define VBE_MODE_LINEAR 128

#define VBE_MODEL_TEXT 0
#define VBE_MODEL_DIRECT 6

#define VBE_EDID_SIZE 128

typedef struct [[gnu::packed]] {
    uint16_t offset;
    uint16_t segment;
} far_ptr_t;

typedef struct [[gnu::packed]] {
    uint8_t signature[4];
    uint16_t version;
    far_ptr_t oem_string;
    uint8_t capabilities[4];
    far_ptr_t video_modes;
    uint16_t total_memory;
    uint16_t oem_software_revision;
    far_ptr_t oem_vendor_name;
    far_ptr_t oem_product_name;
    far_ptr_t oem_product_revision;
    uint8_t reserved[222];
    uint8_t oem_data[256];
} vbe_info_t;

typedef struct [[gnu::packed]] {
    uint16_t mode_attributes;
    uint8_t window_a_attributes;
    uint8_t window_b_attributes;
    uint16_t window_granularity;
    uint16_t window_size;
    uint16_t window_a_segment;
    uint16_t window_b_segment;
    far_ptr_t window_function;
    uint16_t pitch;
    uint16_t width;
    uint16_t height;
    uint8_t char_width;
    uint8_t char_height;
    uint8_t num_planes;
    uint8_t bits_per_pixel;
    uint8_t num_banks;
    uint8_t memory_model;
    uint8_t bank_size;
    uint8_t num_image_pages;
    uint8_t reserved0;
    uint8_t red_mask_size;
    uint8_t red_field_pos;
    uint8_t green_mask_size;
    uint8_t green_field_pos;
    uint8_t blue_mask_size;
    uint8_t blue_field_pos;
    uint8_t rsvd_mask_size;
    uint8_t rsvd_field_pos;
    uint8_t direct_color_attrs;
    uint32_t physical_base_ptr;
    uint32_t reserved1;
    uint16_t reserved2;
    uint16_t linear_pitch;
    uint8_t num_image_pages_banked;
    uint8_t num_image_pages_linear;
    uint8_t linear_red_mask_size;
    uint8_t linear_red_field_pos;
    uint8_t linear_green_mask_size;
    uint8_t linear_green_field_pos;
    uint8_t linear_blue_mask_size;
    uint8_t linear_blue_field_pos;
    uint8_t linear_rsvd_mask_size;
    uint8_t linear_rsvd_field_pos;
    uint32_t max_pixel_clock;
    uint8_t reserved3[190];
} vbe_mode_info_t;

static andromeda_framebuffer_t console_fb_data = {
        .address = 0xb8000,
        .mode =
                {
                        .pitch = 160,
                        .width = 80,
                        .height = 25,
                        .bits_per_pixel = 16,
                        .memory_model = ANDROMEDA_MEMORY_MODEL_CGA_TEXT,
                },
};
andromeda_framebuffer_t *console_fb = &console_fb_data;

static bool have_vbe;
static bool have_edid;

static bool vbe_active;

typedef struct {
    andromeda_framebuffer_t fb;
    uint16_t vbe_mode;
} vbe_mode_t;

static vbe_mode_t *avail_modes;
static size_t num_modes;

static void *edid;
static size_t edid_size;
//static unsigned char edid[VBE_EDID_SIZE];

static bool iter_modes(vbe_info_t *controller, void (*cb)(vbe_mode_t *mode, void *ctx), void *ctx) {
    bool vbe3 = controller->version >= VBE_3_0;
    uint32_t cur = seg_to_lin(controller->video_modes.segment, controller->video_modes.offset);

    for (;;) {
        uint16_t mode;
        copy_from_phys(&mode, cur, sizeof(mode));
        cur += sizeof(mode);
        if (mode == 0xffff) break;

        vbe_mode_info_t info;
        regs_t regs = {.eax = 0x4f01, .ecx = mode};
        regs.edi = lin_to_seg((uintptr_t)&info - KERN_VIRT_BASE, &regs.es);
        intcall(0x10, &regs);

        if (!VBE_SUCCESS(regs.eax)) {
            printk("vbe: failed to get mode info for 0x%x: 0x%x\n", mode, VBE_STATUS(regs.eax));
            return false;
        }

        if ((info.mode_attributes & (VBE_MODE_LINEAR | VBE_MODE_SUPPORTED)) != (VBE_MODE_LINEAR | VBE_MODE_SUPPORTED)) {
            continue;
        }

        vbe_mode_t out = {
                .fb =
                        {
                                .address = info.physical_base_ptr,
                                .mode =
                                        {
                                                .pitch = vbe3 ? info.linear_pitch : info.pitch,
                                                .width = info.width,
                                                .height = info.height,
                                                .bits_per_pixel = info.bits_per_pixel,
                                        },
                        },
                .vbe_mode = (mode & ~0x800) | 0x8000,
        };

        switch (info.memory_model) {
        case VBE_MODEL_TEXT: out.fb.mode.memory_model = ANDROMEDA_MEMORY_MODEL_CGA_TEXT; break;
        case VBE_MODEL_DIRECT:
            out.fb.mode.memory_model = ANDROMEDA_MEMORY_MODEL_RGB;
            out.fb.mode.rgb.red.field_pos = vbe3 ? info.linear_red_field_pos : info.red_field_pos;
            out.fb.mode.rgb.red.mask_size = vbe3 ? info.linear_red_mask_size : info.red_mask_size;
            out.fb.mode.rgb.green.field_pos = vbe3 ? info.linear_green_field_pos : info.green_field_pos;
            out.fb.mode.rgb.green.mask_size = vbe3 ? info.linear_green_mask_size : info.green_mask_size;
            out.fb.mode.rgb.blue.field_pos = vbe3 ? info.linear_blue_field_pos : info.blue_field_pos;
            out.fb.mode.rgb.blue.mask_size = vbe3 ? info.linear_blue_mask_size : info.blue_mask_size;
            break;
        default: continue;
        }

        cb(&out, ctx);
    }

    return true;
}

static void count_modes_cb(vbe_mode_t *, void *) {
    num_modes += 1;
}

static void add_modes_cb(vbe_mode_t *mode, void *ptr) {
    size_t *ctx = ptr;
    ASSERT(*ctx < num_modes);
    avail_modes[(*ctx)++] = *mode;
}

static bool list_modes(vbe_info_t *controller) {
    if (!iter_modes(controller, count_modes_cb, nullptr)) return false;
    avail_modes = vmalloc(num_modes * sizeof(*avail_modes));
    size_t i = 0;
    return iter_modes(controller, add_modes_cb, &i);
}

void init_vbe() {
    vbe_info_t info = {
            .signature = "VBE2",
    };
    regs_t regs = {.eax = 0x4f00};
    regs.edi = lin_to_seg((uintptr_t)&info - KERN_VIRT_BASE, &regs.es);
    intcall(0x10, &regs);

    if (!VBE_SUCCESS(regs.eax)) {
        if (VBE_SUPPORTED(regs.eax)) {
            printk("vbe: failed to get controller information (0x%x)\n", VBE_STATUS(regs.eax));
        }
        return;
    }

    if (memcmp(info.signature, "VESA", 4)) {
        printk("vbe: invalid signature in controller information\n");
        return;
    }

    printk("vbe: bios supports vbe %u.%u\n", info.version >> 8, info.version & 0xff);

    if (info.version < VBE_MIN_VERSION) {
        printk("vbe: unsupported version\n");
        return;
    }

    if (!list_modes(&info)) return;

    have_vbe = true;
    int error = vfs_mknod(nullptr, "/dev/video/vbe", 14, S_IFCHR | 0600, DEVICE_ID(DRIVER_VIDEO, 0));
    if (unlikely(error)) panic("vbe: failed to create device file (%d)", error);

    regs = (regs_t){.eax = 0x4f15};
    intcall(0x10, &regs);

    if (VBE_SUCCESS(regs.eax)) {
        unsigned char buffer[128];
        printk("vbe: edid supported\n");

        regs = (regs_t){.eax = 0x4f15, .ebx = 1};
        regs.edi = lin_to_seg((uintptr_t)buffer - KERN_VIRT_BASE, &regs.es);
        intcall(0x10, &regs);
        if (!VBE_SUCCESS(regs.eax)) {
            printk("vbe: failed to get edid info: 0x%x\n", VBE_STATUS(regs.eax));
            return;
        }

        // checksum
        uint8_t sum = 0;
        for (int i = 0; i < 128; i++) sum += buffer[i];

        if (sum != 0) {
            printk("vbe: invalid edid checksum\n");
            return;
        }

        // read extensions
        edid_size = (buffer[126] + 1) * 128;
        edid = vmalloc(edid_size);
        memcpy(edid, buffer, 128);

        for (int i = 0; i < buffer[126]; i++) {
            regs = (regs_t){.eax = 0x4f15, .ebx = 1, .edx = i + 1};
            regs.edi = lin_to_seg((uintptr_t)buffer - KERN_VIRT_BASE, &regs.es);
            intcall(0x10, &regs);
            if (!VBE_SUCCESS(regs.eax)) {
                printk("vbe: failed to get edid extension: 0x%x\n", VBE_STATUS(regs.eax));
                return;
            }

            memcpy(edid + (i + 1) * 128, buffer, 128);
        }

        have_edid = true;
    }
}

static void vbe_fb_free(file_t *) {
    screen_enable(true);
    vbe_active = false;
}

static const file_ops_t vbe_fb_ops = {.free = vbe_fb_free};

static int vbe_ioctl(file_t *, unsigned long request, void *arg) {
    switch (request) {
    case IOCTL_LIST_MODES: {
        int error = -verify_pointer((uintptr_t)arg, sizeof(andromeda_video_modes_t));
        if (unlikely(error)) return error;

        andromeda_video_modes_t buffer;
        error = -user_memcpy(&buffer, arg, sizeof(buffer));
        if (unlikely(error)) return error;

        if (buffer.start > num_modes) return -EINVAL;

        error = -verify_pointer((uintptr_t)buffer.modes, buffer.capacity * sizeof(*buffer.modes));
        if (unlikely(error)) return error;

        size_t avail = num_modes - buffer.start;
        size_t count = avail < buffer.capacity ? avail : buffer.capacity;

        for (size_t i = 0; i < count; i++) {
            error = -user_memcpy(&buffer.modes[i], &avail_modes[i + buffer.start].fb.mode, sizeof(*buffer.modes));
            if (unlikely(error)) return error;
        }

        return avail;
    }
    case IOCTL_SET_MODE: {
        if (vbe_active) return -EBUSY;

        int error = -verify_pointer((uintptr_t)arg, sizeof(andromeda_framebuffer_request_t));
        if (unlikely(error)) return error;

        andromeda_framebuffer_request_t request;
        error = -user_memcpy(&request, arg, sizeof(request));
        if (unlikely(error)) return error;

        if (unlikely(request.flags & ~O_CLOEXEC)) return -EINVAL;
        if (unlikely(request.mode_index < 0)) return -EINVAL;
        if (unlikely((unsigned)request.mode_index >= num_modes)) return -EINVAL;

        vbe_mode_t *mode = &avail_modes[request.mode_index];

        screen_disable();

        regs_t regs = {.eax = 0x4f02, .ebx = mode->vbe_mode};
        intcall(0x10, &regs);
        if (!VBE_SUCCESS(regs.eax)) {
            screen_enable(false);
            printk("vbe: failed to set mode 0x%x: 0x%x\n", mode->vbe_mode, VBE_STATUS(regs.eax));
            return -EIO;
        }

        int fd = fd_alloc();
        if (unlikely(fd < 0)) {
            screen_enable(true);
            return fd;
        }

        inode_t *inode = create_anonymous_inode(S_IFCHR, DEVICE_ID(DRIVER_RESERVED, next_reserved_minor()));
        file_t *file;
        error = -open_inode(&file, nullptr, inode, O_RDWR, &vbe_fb_ops);
        if (unlikely(error)) {
            screen_enable(true);
            fd_free(fd);
            return error;
        }

        request.framebuffer = mode->fb;

        error = -user_memcpy(arg, &request, sizeof(request));
        if (unlikely(error)) {
            screen_enable(true);
            fd_free(fd);
            return error;
        }

        fd_assoc(fd, file, request.flags & O_CLOEXEC ? FD_CLOEXEC : 0);
        file_deref(file);
        vbe_active = true;
        return fd;
    }
    case IOCTL_GET_EDID: {
        if (!have_edid) return -ENODATA;
        andromeda_edid_request_t request;

        int error = -verify_pointer((uintptr_t)arg, sizeof(request));
        if (unlikely(error)) return error;

        error = -user_memcpy(&request, arg, sizeof(request));
        if (unlikely(error)) return error;

        error = -verify_pointer((uintptr_t)request.buffer, request.capacity);
        if (unlikely(error)) return error;

        error = -user_memcpy(request.buffer, edid, request.capacity < edid_size ? request.capacity : edid_size);
        if (unlikely(error)) return error;

        return edid_size;
    }
    default: return -ENOTTY;
    }
}

static const file_ops_t vbe_file_ops = {
        .ioctl = vbe_ioctl,
};

int open_video(uint32_t minor, file_t *file, int) {
    if (!have_vbe || minor) return ENXIO;
    file->ops = &vbe_file_ops;
    return 0;
}
