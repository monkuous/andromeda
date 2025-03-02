#!/bin/sh
set -ue
# usage: switch.sh package

if test ! -L bootstrap.link; then
    printf '%s: must be ran from within the build directory\n' "$0" >&2
    exit 2
fi

echo "$1" > active-package
xbstrap configure -c "$1"
