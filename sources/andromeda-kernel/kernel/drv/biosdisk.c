#include "biosdisk.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/layout.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "mem/vmem.h"
#include "string.h"
#include "util/panic.h"
#include "util/print.h"
#include <errno.h>
#include <stdint.h>

#define MAX_BLOCKS 127

static struct {
    uint32_t phys;
    void *virt;
} biosdisk_bounce;

typedef struct {
    bdev_t base;
    uint64_t lba0;
    uint8_t drive;
} bios_bdev_t;

typedef struct [[gnu::packed, gnu::aligned(8)]] {
    uint16_t params_size;
    uint16_t flags;
    uint32_t cylinders;
    uint32_t heads;
    uint32_t sectors;
    uint64_t blocks;
    uint16_t block_size;
} bios_params_t;

typedef struct [[gnu::packed, gnu::aligned(8)]] {
    uint16_t packet_size;
    uint16_t num_blocks;
    uint16_t dest_off;
    uint16_t dest_seg;
    uint64_t block;
} bios_dap_t;

static int do_read(bdev_t *ptr, uint32_t phys, uint64_t block, size_t count) {
    ASSERT(count);
    ASSERT(phys + (count << ptr->block_shift) <= 0x100000);

    bios_bdev_t *self = (bios_bdev_t *)ptr;
    block += self->lba0;

    while (count) {
        bios_dap_t dap;
        dap.packet_size = sizeof(dap);
        dap.num_blocks = count < MAX_BLOCKS ? count : MAX_BLOCKS;
        dap.dest_off = lin_to_seg(phys, &dap.dest_seg);
        dap.block = block;

        regs_t regs = {
                .eax = 0x4200,
                .edx = self->drive,
                .esi = KERN_TO_PHYS((uintptr_t)&dap),
        };
        intcall(0x13, &regs);
        if (regs.eflags & 1) return EIO;

        phys += (uint32_t)dap.num_blocks << self->base.block_shift;
        block += dap.num_blocks;
        count -= dap.num_blocks;
    }

    return 0;
}

static int biosdisk_rvirt(bdev_t *ptr, void *buffer, uint64_t block, size_t count) {
    size_t page_blocks = PAGE_SIZE >> ptr->block_shift;

    while (count) {
        size_t cur_blocks = page_blocks < count ? page_blocks : count;
        size_t cur_bytes = cur_blocks << ptr->block_shift;

        int error = do_read(ptr, biosdisk_bounce.phys, block, cur_blocks);
        if (unlikely(error)) return error;

        memcpy(buffer, biosdisk_bounce.virt, cur_bytes);

        buffer += cur_bytes;
        block += cur_blocks;
        count -= cur_blocks;
    }

    return 0;
}

static int biosdisk_rphys(bdev_t *ptr, uint32_t phys, uint64_t block, size_t count) {
    if (phys < 0x100000) {
        size_t direct_blocks = (0x100000 - phys) >> ptr->block_shift;

        if (direct_blocks) {
            int error = do_read(ptr, phys, block, count);
            if (unlikely(error)) return error;

            phys += direct_blocks << ptr->block_shift;
            block += direct_blocks;
            count -= direct_blocks;
        }
    }

    size_t page_blocks = PAGE_SIZE >> ptr->block_shift;

    while (count) {
        size_t cur_blocks = page_blocks < count ? page_blocks : count;
        size_t cur_bytes = cur_blocks << ptr->block_shift;

        int error = do_read(ptr, biosdisk_bounce.phys, block, cur_blocks);
        if (unlikely(error)) return error;

        block += cur_blocks;
        count -= cur_blocks;

        void *copy_src = biosdisk_bounce.virt;

        while (cur_bytes) {
            uint32_t pgoff = phys & PAGE_MASK;
            uint32_t pgrem = PAGE_SIZE - pgoff;
            uint32_t ncopy = pgrem < cur_bytes ? pgrem : cur_bytes;

            memcpy(pmap_tmpmap(phys) + pgoff, copy_src, ncopy);

            phys += ncopy;
            copy_src += ncopy;
            cur_bytes -= ncopy;
        }
    }

    return 0;
}

static const bdev_ops_t bios_bdev_ops = {
        .rvirt = biosdisk_rvirt,
        .rphys = biosdisk_rphys,
};

static bios_bdev_t *bios_drives;
static size_t bios_drive_count;

static void alloc_bounce_buf() {
    page_t *page = pmem_alloc_slow(1, 0xfffff);
    if (unlikely(!page)) panic("biosdisk: failed to allocate bounce buffer");

    biosdisk_bounce.phys = page_to_phys(page);

    uintptr_t virt = vmem_alloc(PAGE_SIZE);
    pmap_map(virt, biosdisk_bounce.phys, PAGE_SIZE, 0);
    biosdisk_bounce.virt = (void *)virt;
}

static size_t create_drive() {
    size_t old_size = bios_drive_count * sizeof(*bios_drives);
    size_t new_size = old_size + sizeof(*bios_drives);
    bios_bdev_t *buffer = vmalloc(new_size);
    memcpy(buffer, bios_drives, old_size);
    vmfree(bios_drives, old_size);
    bios_drives = buffer;
    return bios_drive_count++;
}

static bool process_drive(uint8_t id, uint64_t boot_lba) {
    bios_params_t params;
    params.params_size = sizeof(params);

    regs_t regs = {.eax = 0x4800, .edx = id, .esi = KERN_TO_PHYS((uintptr_t)&params)};
    intcall(0x13, &regs);

    if (regs.eflags & 1) return false;
    if (!params.blocks || !params.block_size) return false;
    if (params.block_size & (params.block_size - 1)) return false;
    if (params.block_size > PAGE_SIZE) return false;

    size_t minor = create_drive();
    bios_bdev_t *bdev = &bios_drives[minor];
    memset(bdev, 0, sizeof(*bdev));

    bdev->base.ops = &bios_bdev_ops;
    bdev->base.blocks = params.blocks;
    bdev->base.block_shift = __builtin_ctz(params.block_size);
    bdev->drive = id;

    unsigned char name_buffer[32];
    size_t name_length = snprintk(name_buffer, sizeof(name_buffer), "/dev/disk%u", minor);

    int error = vfs_mknod(nullptr, name_buffer, name_length, S_IFBLK | 0644, DEVICE_ID(DRIVER_BIOSDISK, minor));
    if (unlikely(error)) panic("biosdisk: mknod failed (%d)", error);

    if (boot_lba != UINT64_MAX) {
        error = vfs_symlink(nullptr, "/dev/bootdisk", 13, name_buffer, name_length);
        if (unlikely(error)) panic("biosdisk: symlink failed (%d)", error);

        if (boot_lba == 0) {
            error = vfs_symlink(nullptr, "/dev/bootvol", 12, name_buffer, name_length);
            if (unlikely(error)) panic("biosdisk: symlink failed (%d)", error);
        }
    }

    // TODO: Partitions

    return true;
}

static void discover_drives(uint8_t boot_drive, uint64_t boot_lba) {
    regs_t regs = {.eax = 0x800, .edx = 0x80};
    intcall(0x13, &regs);
    size_t num_hd = regs.edx & 0xff;

    bool have_boot = false;

    for (unsigned id = 0x80; id < 0x100; id++) {
        if (process_drive(id, id == boot_drive ? boot_lba : UINT64_MAX)) {
            if (id == boot_drive) have_boot = true;
            if (--num_hd == 0) break;
        }
    }

    if (!have_boot && !process_drive(boot_drive, boot_lba)) {
        panic("biosdisk: failed to initialize boot drive");
    }
}

void init_biosdisk(uint8_t boot_drive, uint64_t boot_lba) {
    alloc_bounce_buf();
    discover_drives(boot_drive, boot_lba);
}

bdev_t *resolve_biosdisk(uint32_t id) {
    if (unlikely(id >= bios_drive_count)) return nullptr;

    return &bios_drives[id].base;
}
