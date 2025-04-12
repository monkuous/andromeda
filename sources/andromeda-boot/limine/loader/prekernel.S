.section ".rodata", "a", @progbits

.balign 4
.globl prekernel_start, prekernel_end
.type prekernel_start, @object
prekernel_start:
    .incbin "limine-prekernel.bin"
prekernel_end:
.size prekernel_start, . - prekernel_start

.section ".note.GNU-stack", "", @progbits
