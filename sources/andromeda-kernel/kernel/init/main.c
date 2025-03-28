#include "compiler.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "fs/ramfs.h"
#include "fs/vfs.h"
#include "init/bios.h"
#include "mem/bootmem.h"
#include "mem/memdetect.h"
#include "proc/process.h"
#include "util/panic.h"
#include "util/print.h"
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>

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
    error = vfs_chdir(root);
    if (unlikely(error)) panic("failed to set working directory (%d)", error);
    file_deref(root);

    vfs_umask(022);

    error = vfs_mknod(nullptr, "boot", 4, S_IFDIR | 0755, 0);
    if (unlikely(error)) panic("failed to create /boot (%d)", error);

    error = vfs_mknod(nullptr, "dev", 3, S_IFDIR | 0755, 0);
    if (unlikely(error)) panic("failed to create /dev (%d)", error);
}

[[noreturn, gnu::used]] void kernel_main([[maybe_unused]] uint64_t boot_lba, [[maybe_unused]] uint8_t boot_drive) {
    init_gdt();
    init_idt();
    init_video();
    printk("\nStarting Andromeda...\n");
    detect_memory();
    bootmem_handover();
    init_proc();
    init_vfs();

    panic("TODO");
}
