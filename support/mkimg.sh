#!/bin/sh
set -ue
# usage: mkimg.sh output size sysroot

dd of="$1" bs=1M count=0 seek="$2" status=none
dd if=pkg-builds/andromeda-kernel/bcode/mbr.bin of="$1" conv=notrunc status=none
sfdisk -q "$1" << EOF
label: dos
start=1M, type=0c, bootable
EOF

export MTOOLSRC=$(mktemp)
cleanup () {
    rm "$MTOOLSRC"
}
trap cleanup EXIT
cat > "$MTOOLSRC" << EOF
drive p:
    file="$1" partition=1
EOF

# 512 byte sectors, partition starts at 2048 sectors
mformat -F -B pkg-builds/andromeda-kernel/bcode/fat32.bin -S 2 -H 2048 p:
mcopy -spm "$3/boot"/* p:/

"$(dirname "$(readlink -f -- "$0")")/mkinitrd.sh" system-root | mcopy - p:/andromed.img
