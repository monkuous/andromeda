#include "compiler.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "drv/biosdisk.h"
#include "drv/console.h"
#include "drv/device.h"
#include "drv/loopback.h"
#include "fs/detect.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/bootmem.h"
#include "mem/memdetect.h"
#include "proc/exec.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "util/panic.h"
#include "util/print.h"
#include <andromeda/string.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static void init_video() {
    // ensure video mode is 3 (80x25 color text)
    regs_t regs = {.eax = 0xf00};
    intcall(0x10, &regs);

    if ((regs.eax & 0xff) != 3) {
        regs = (regs_t){.eax = 3};
        intcall(0x10, &regs);
    }
}

// Mounts a ramfs on /, sets up cwd and umask, and creates some of the basic folder structure
static void init_vfs() {
    struct ramfs_create_ctx ramfs_ctx = {.mode = 0755};
    int error = vfs_mount(nullptr, "/", 1, ramfs_create, &ramfs_ctx);
    if (unlikely(error)) panic("failed to mount root (%d)", error);

    file_t *root;
    error = vfs_open(&root, nullptr, "/", 1, O_DIRECTORY, 0);
    if (unlikely(error)) panic("failed to open root (%d)", error);
    error = vfs_chroot(root);
    if (unlikely(error)) panic("failed to set working directory (%d)", error);
    file_deref(root);

    error = vfs_mknod(nullptr, "boot", 4, S_IFDIR | 0755, 0);
    if (unlikely(error)) panic("failed to create /boot (%d)", error);

    error = vfs_mknod(nullptr, "dev", 3, S_IFDIR | 0755, 0);
    if (unlikely(error)) panic("failed to create /dev (%d)", error);

    error = vfs_mount(nullptr, "dev", 3, ramfs_create, &ramfs_ctx);
    if (unlikely(error)) panic("failed to mount /dev (%d)", error);

    error = vfs_mknod(nullptr, "realroot", 8, S_IFDIR | 0755, 0);
    if (unlikely(error)) panic("failed to create /realroot (%d)", error);
}

static dev_t get_boot_volume() {
    file_t *file;
    int error = vfs_open(&file, nullptr, "/dev/bootvol", 12, O_RDONLY, 0);
    if (unlikely(error)) panic("failed to open boot volume (%d)", error);
    struct stat stat;
    error = vfs_fstat(file, &stat);
    file_deref(file);
    if (unlikely(error)) panic("failed to stat boot volume (%d)", error);

    ASSERT(S_ISBLK(stat.st_mode));
    return stat.st_rdev;
}

static void mount_boot() {
    printk("kernel: mounting /boot\n");

    bdev_t *bdev = resolve_bdev(get_boot_volume());
    if (unlikely(!bdev)) panic("failed to resolve boot volume");

    int error = vfs_mount(nullptr, "/boot", 5, fsdetect, bdev);
    if (unlikely(error)) panic("failed to mount /boot (%d)", error);
}

static void mount_initrd() {
    printk("kernel: mounting initrd\n");

    dev_t loopback_dev;

    file_t *file;
    int error = vfs_open(&file, nullptr, "/boot/andromed.img", 18, O_RDONLY, 0);
    if (unlikely(error)) panic("failed to open initrd at /boot/andromed.img (%d)", error);
    error = create_loopback(&loopback_dev, file, 512);
    file_deref(file);
    if (unlikely(error)) panic("failed to create initrd loopback device (%d)", error);

    error = vfs_mknod(nullptr, "/dev/initrd", 11, S_IFBLK | 0600, loopback_dev);
    if (unlikely(error)) panic("failed to create initrd device file (%d)", error);

    bdev_t *bdev = resolve_bdev(loopback_dev);
    if (unlikely(!bdev)) panic("failed to resolve loopback device");

    error = vfs_mount(nullptr, "/realroot", 9, fsdetect, bdev);
    if (unlikely(error)) panic("failed to mount initrd (%d)", error);
}

static void chroot_to_initrd() {
    int error = vfs_mvmount(nullptr, "/boot", 5, nullptr, "/realroot/boot", 14);
    if (unlikely(error)) panic("failed to move /boot (%d)", error);

    error = vfs_mvmount(nullptr, "/dev", 4, nullptr, "/realroot/dev", 13);
    if (unlikely(error)) panic("failed to move /dev (%d)", error);

    file_t *file;
    error = vfs_open(&file, nullptr, "/realroot", 9, O_RDONLY | O_DIRECTORY, 0);
    if (unlikely(error)) panic("failed to open /realroot (%d)", error);

    error = vfs_chroot(file);
    if (unlikely(error)) panic("failed to chroot to initrd (%d)", error);

    file_deref(file);
}

[[noreturn]] static void run_init() {
    static const andromeda_tagged_string_t init_name = {"/sbin/init", 10};
    static const andromeda_tagged_string_t environment[] = {
            {"HOME=/root", 10},
    };

    printk("kernel: starting init process\n");

    file_t *file;
    int error = vfs_open(&file, nullptr, init_name.data, init_name.length, O_RDONLY, 0);
    if (unlikely(error)) panic("failed to open %S (%d)", init_name.data, init_name.length, error);

    error = execute(file, &init_name, 1, environment, sizeof(environment) / sizeof(*environment), false);
    file_deref(file);
    if (unlikely(error)) panic("failed to start init process (%d)", error);

    idt_frame_t frame = current->regs;
    idt_return(&frame);
}

[[noreturn, gnu::used]] void kernel_main(uint64_t boot_lba, uint8_t boot_drive) {
    init_gdt();
    init_idt();
    init_video();
    printk("\nStarting Andromeda...\n\n");
    detect_memory();
    bootmem_handover();
    init_proc();
    init_vfs();
    init_console();
    init_biosdisk(boot_drive, boot_lba);
    mount_boot();
    mount_initrd();
    chroot_to_initrd();
    run_init();
}
