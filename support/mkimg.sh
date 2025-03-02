#!/bin/sh
set -ue
# usage: mkimg.sh output size sysroot

rootoffs=16
rootsize=$(($2 - rootoffs - 1))
rblksize=1024
rootblks=$((rootsize * 1024 * 1024 / rblksize))

bootoffs=1
bootsize=$((rootoffs - bootoffs))
mtimgarg="$1@@${bootoffs}M"

# Create and format image
dd of="$1" bs=1M count=0 seek="$2" status=none
sfdisk -q "$1" << EOF
label: gpt
start=${bootoffs}M,size=${bootsize}M,type=uefi
start=${rootoffs}M,size=${rootsize}M
EOF
mformat -i "$mtimgarg" -S 2 -H $((bootoffs * 2048)) -T $((bootsize * 2048)) ::
tar -cC "$3" --numeric-owner --owner=0 --group=0 --exclude=./boot --exclude=./etc/xbstrap . \
    | mke2fs -qE offset=$((rootoffs * 1024 * 1024)) -d - -b "$rblksize" "$1" "$rootblks"

# Set up boot partition
mcopy -spmi "$mtimgarg" "$3/boot"/* ::/
