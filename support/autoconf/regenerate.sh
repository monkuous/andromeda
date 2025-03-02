#!/bin/sh
set -ue
# usage: regenerate.sh [args]...

find . '(' -name configure.ac -o -name configure.in ')' -type f -print0 \
    | LC_ALL=C sort -z \
    | xargs -0 autoreconf -fvi "$@"
