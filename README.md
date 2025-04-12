# Andromeda

Andromeda is a BIOS bootloader that provides a POSIX-like preboot environment.

## Features

- Non-preemptible single-stack monolithic kernel
- BIOS-based disk driver
- Read-only support for FAT12/16/32 and ISO9660, as well as a read-write ramfs implementation
- Demand paging
- Signals
- Futexes
- Boot protocol implementations run in userspace
- The boot configuration is just a bash script

## Building

Andromeda uses [xbstrap](https://github.com/managarm/xbstrap) as its build system.

To begin, create a build directory and initialize it:
```sh
mkdir build && cd build
cat > bootstrap-site.yml << EOF
define_options:
  build-type: release # the meson build type. only affects first-party packages and mlibc
  cpu: i486           # the target architecture level to compile for (min: i486)
  debugcon: 'false'   # set this to true if you want the kernel log to be written to port 0xe9
  lto: 'true'         # enables/disables link-time optimization. only affects first-party packages and mlibc
EOF
xbstrap init ..
```

### Disk image

To build the system and create a FAT32 disk image, simply run `xbstrap run make-image`.
The disk image will be written to `andromeda.img`. If you want to write it somewhere
else or use a different size, build the system and run the image generation script manually:
```sh
xbstrap install andromeda
../support/mkimg.sh (image name) (image size in megabytes) system-root
```

This script can also be used to install Andromeda to a block device, in which case
the size parameter is ignored. Note that this will overwrite the partition table
on the specified device and create a freshly formatted partition spanning the
entire disk; back up all data stored on the disk before doing this.

### Something else

If you want something other than a disk image, first build the system manually:
`xbstrap install andromeda`.

An Andromeda setup consists of three components: the boot code, the kernel, and the initrd.

#### Boot code and kernel

For a typical partitioned hard-drive setup:
- The MBR boot code (located at pkg-builds/andromeda-kernel/bcode/mbr.bin) should be written to
  the first sector of the device. This boot code will inspect the partition table to determine
  which volume to load the VBR from; take care not to overwrite it.
- A FAT32 partition should be made and marked as active, and the VBR boot code (located at
  pkg-builds/andromeda-kernel/bcode/fat32.bin) should be written to the first sector of
  this partition. This boot code will load the kernel from the filesystem; it must be named
  `andromed.sys` and be located in the root directory of the partition.
An unpartitioned setup is similar, except without the MBR. Instead, the FAT32 VBR boot code should
be written to the first sector of the device.

#### Initrd

The Andromeda kernel does not use the boot volume as its root filesystem. Instead, it sets up
a loopback block device, backed by `andromed.img` in the root of the boot volume, and mounts
that as the root directory. Any supported filesystem can be used for this, but it is recommended
to use an ISO9660 image, due to its support of POSIX filesystem features via Rock Ridge. To generate an ISO9660 initrd image, run:
```sh
../support/mkinitrd.sh system-root > (output path)
```
Note the `>`: the script writes the result image to standard output.

## Configuration

On startup, `andromeda-init` runs `bash` as a login shell. The included `.bash_profile` for
the `root` user checks if `/boot/andromed.sh` exists, and if so, runs it.

Booting an operating system can be done with the applications installed by `andromeda-boot`:
- `boot-linux` boots a Linux kernel image
- `boot-limine` boots a Limine kernel
