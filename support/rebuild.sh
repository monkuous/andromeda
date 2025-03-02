#!/bin/sh
set -ue
# usage: rebuild.sh

if test ! -L bootstrap.link; then
    printf '%s: must be ran from within the build directory\n' "$0" >&2
    exit 2
fi

pkg="$(cat active-package)"

exec xbstrap install --rebuild "$pkg"
