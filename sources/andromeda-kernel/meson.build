project(
    'andromeda-kernel',
    'c',
    default_options: ['c_std=gnu23', 'warning_level=2'],
    meson_version: '>=1.4.0',
)

objcopy = find_program('objcopy')

if get_option('qemu_debugcon')
    add_project_arguments('-DANDROMEDA_QEMU_DEBUGCON=1', language: 'c')
endif

subdir('bcode')
subdir('kernel')
