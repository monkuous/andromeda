script = files('bcode.lds')[0]

foreach type : ['fat32', 'mbr']
    elf = executable(
        type + '.elf',
        type + '.S',
        build_by_default: false,
        link_args: ['-nostdlib', '-static', '-T' + script.full_path()],
        link_depends: script,
    )

    custom_target(
        type + '.bin',
        build_by_default: true,
        command: [objcopy, '@INPUT@', '@OUTPUT@', '-Obinary', '-j.bcode'],
        input: elf,
        output: type + '.bin',
    )
endforeach
