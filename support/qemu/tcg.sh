#!/bin/sh
set -ue
# usage: tcg.sh image [args]...

img="$1"
shift 1

echo Starting QEMU
qemu-system-i386 -debugcon stdio -drive format=raw,file="$img" "$@"
