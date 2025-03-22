ENTRY(_start)
OUTPUT_ARCH(i386)
OUTPUT_FORMAT(elf32-i386)

PHDRS {
    init PT_LOAD FLAGS(5);
    text PT_LOAD FLAGS(5);
    data PT_LOAD FLAGS(6);
}

SECTIONS {
    . = 0x8000;
    .text.init : { *(.text.init) } :init
    ASSERT(. <= 0x10000, ".text.init too large")

    . += __kern_virt_base;
    .text : AT(ADDR(.text) - __kern_virt_base) { *(.text .text.* .rodata .rodata.*) } :text
    .data : AT(ADDR(.data) - __kern_virt_base) { *(.data .data.*) } :data
    .bss  : AT(ADDR(.bss) - __kern_virt_base) { __bss_start = .; *(.bss .bss.* COMMON) __bss_end = .; } :data

    _end = .;

    ASSERT((_end - __kern_virt_base) <= 0x90000, "kernel too large")
}
