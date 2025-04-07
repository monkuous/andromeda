project(
    'util-andromeda',
    'c',
    default_options: ['c_std=gnu23', 'warning_level=2'],
    meson_version: '>=1.4.0',
)

foreach name : ['hexdump', 'kbmods', 'mount', 'umount']
    executable(name, name + '.c', install: true)
endforeach
