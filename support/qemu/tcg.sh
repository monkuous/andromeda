#!/bin/sh
set -ue
# usage: tcg.sh image [args]...

img="$1"
fwd=tools/ovmf
shift 1

echo Starting QEMU
qemu-system-riscv64 -cpu rva22s64 -M virt \
        -drive if=pflash,readonly=on,format=raw,file="$fwd/code.fd" \
        -drive if=pflash,format=raw,file="$fwd/vars.fd" -device ramfb \
        -device qemu-xhci -device usb-kbd -device virtio-rng-pci \
        -device ahci,id=ahci -device ide-hd,bus=ahci.0,drive=hd0 \
        -drive if=none,id=hd0,format=raw,file="$img" "$@"
