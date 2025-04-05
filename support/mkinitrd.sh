#!/bin/sh
set -ue
# usage: mkinitrd.sh sysroot

xorriso -as mkisofs -R -r -uid 0 -gid 0 "$1"
