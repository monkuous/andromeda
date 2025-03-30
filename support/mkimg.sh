#!/bin/sh
set -ue
# usage: mkimg.sh output size sysroot

dd of="$1" bs=1M count=0 seek="$2" status=none
mformat -i "$1" -F -B pkg-builds/andromeda-kernel/bcode/fat32.bin ::
mcopy -spmi "$1" "$3/boot"/* ::/
xorriso -as mkisofs -R -r -uid 0 -gid 0 "$3" | mcopy -i "$1" - ::/andromed.img
