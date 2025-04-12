prekernel_bin = custom_target(
    command: [objcopy, '@INPUT@', '@OUTPUT@', '-Obinary'],
    input: prekernel,
    output: 'limine-prekernel.bin',
)

executable(
    'boot-limine',
    'cpufeat.c',
    'framebuffer.c',
    'hhdm.c',
    'image-elf.c',
    'image.c',
    'main.c',
    'memmap.c',
    'module.c',
    'paging.c',
    'pathutil.c',
    'prekernel.S',
    'requests.c',
    'rsdp.c',
    prekernel_bin,
    c_args: limine_args,
    include_directories: [inc, limine_inc],
    install: true,
    link_with: libboot,
)
