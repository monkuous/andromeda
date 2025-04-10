project(
    'boot',
    'c',
    default_options: ['c_std=gnu23', 'warning_level=2'],
    meson_version: '>=1.4.0',
)

libboot = shared_library('boot', 'libboot.c', install: true)
executable('boot-linux', 'linux.c', install: true, link_with: libboot)
