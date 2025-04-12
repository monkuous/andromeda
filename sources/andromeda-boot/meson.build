project(
    'boot',
    'c',
    default_options: ['c_std=gnu23', 'warning_level=2'],
    meson_version: '>=1.4.0',
)

inc = include_directories('include')

objcopy = find_program('objcopy')

subdir('libboot')
subdir('limine')
subdir('linux')
