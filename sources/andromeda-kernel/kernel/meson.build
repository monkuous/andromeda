script = files('kernel.lds')[0]

kernel_elf = executable(
    'kernel.elf',
    'cpu/gdt.c',
    'cpu/idt.c',
    'cpu/idt.S',
    'init/main.c',
    'init/main.S',
    'mem/bootmem.c',
    'mem/kmalloc.c',
    'mem/memdetect.c',
    'mem/pmap.c',
    'mem/pmem.c',
    'mem/vmem.c',
    'util/panic.c',
    'util/print.c',
    'util/string.c',
    build_by_default: false,
    c_args: [
        '-ffreestanding',
        '-fno-asynchronous-unwind-tables',
        '-fno-pie',
        '-fno-stack-protector',
        '-mgeneral-regs-only',
        '-mregparm=3',
    ],
    link_args: ['-nostdlib', '-static', '-T' + script.full_path()],
    link_depends: script,
)

custom_target(
    'kernel.sys',
    build_by_default: true,
    command: [objcopy, '@INPUT@', '@OUTPUT@', '-Obinary'],
    input: kernel_elf,
    install: true,
    install_dir: '/boot',
    install_mode: 'rw-r--r--',
    output: 'andromed.sys',
)
