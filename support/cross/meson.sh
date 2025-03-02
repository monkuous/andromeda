#!/bin/sh
set -ue
# usage: meson.sh output cpu triple sysroot

target="$2-$3"

cat > "$1" << EOF
[binaries]
ar = '$target-gcc-ar'
c = '$target-gcc'
cpp = '$target-g++'
nm = '$target-gcc-nm'
objcopy = '$target-objcopy'
pkg-config = 'pkgconf'
ranlib = '$target-gcc-ranlib'
strip = '$target-strip'

[host_machine]
system = 'andromeda'
cpu_family = 'x86'
cpu = '$2'
endian = 'little'

[built-in options]
c_args = ['-fdata-sections', '-ffunction-sections', '--sysroot=$4']
c_link_args = ['-Wl,--gc-sections,--sort-section=alignment']
cpp_args = c_args
cpp_link_args = c_link_args
libdir = 'lib'

[properties]
sys_root = '$4'
pkg_config_libdir = '$4/usr/lib/pkgconfig'
EOF
