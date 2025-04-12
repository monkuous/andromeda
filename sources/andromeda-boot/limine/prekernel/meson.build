script = files('prekernel.lds')[0]

prekernel = executable(
    'limine-prekernel',
    'acpi.c',
    'irq.c',
    'memory.c',
    'smp.c',
    'smp.S',
    'start.c',
    'start.S',
    'string.c',
    build_by_default: false,
    c_args: [
        limine_args,
        '-ffreestanding',
        '-fno-asynchronous-unwind-tables',
        '-fno-stack-protector',
        '-m32',
        '-mgeneral-regs-only',
        '-mregparm=3',
        '-Wno-multichar',
    ],
    include_directories: limine_inc,
    link_args: [
        '-m32',
        '-nostdlib',
        '-T' + script.full_path(),
        '-Wl,--no-dynamic-linker',
    ],
    link_depends: script,
    pie: true,
)
