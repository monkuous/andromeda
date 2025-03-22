ENTRY(_start)

SECTIONS {
    .bcode 0x7c00 : { *(.bcode) }
}
