#!/bin/sh
set -ue
# usage: kvm.sh image [args]...

img="$1"
shift 1

echo Starting QEMU
qemu-system-i386 -accel kvm -debugcon stdio -M isapc -drive format=raw,file="$img" "$@"
