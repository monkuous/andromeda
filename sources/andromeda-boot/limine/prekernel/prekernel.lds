ENTRY(_start)
OUTPUT_ARCH(i386)
OUTPUT_FORMAT(elf32-i386)

PHDRS {
    text    PT_LOAD FLAGS(5);
    data    PT_LOAD FLAGS(6);
    dynamic PT_DYNAMIC FLAGS(5);
}

__bss_size4 = ABSOLUTE(ALIGN(SIZEOF(.bss), 4) / 4);

SECTIONS {
    . = 0;
    .text : { LONG(_end - ADDR(.text)); *(.text._start) *(.text .text.*) } :text
    .rodata : { *(.rodata .rodata.* .rel .rel.*) } :text
    .dynamic : { *(.dynamic) } :text :dynamic
    .data : { *(.data .data.*) } :data
    .rela : { *(.rela .rela.*) } :data
    .bss : { __bss_start = .; *(.bss .bss.*) } :data
    _end = .;

    ASSERT(SIZEOF(.rela) == 0, "prekernel contains rela relocations")

    /DISCARD/ : { *(.note.*) }
}
