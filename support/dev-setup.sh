#!/bin/sh
set -ue
# usage: dev-setup.sh [cpu]

if test ! -f bootstrap.yml; then
    printf '%s: must be ran from within the source directory\n' "$0" >&2
    exit 2
fi

dir="$(dirname "$(readlink -f -- "$0")")"

mkdir build
cd build

echo '*' > .gitignore
cat > bootstrap-site.yml << EOF
define_options:
  build-type: debug
  cpu: '${1:-i486}'
  debugcon: 'true'
  lto: 'false'
EOF

xbstrap init ..
"$dir/switch.sh" mlibc
xbstrap install-tool gdb

