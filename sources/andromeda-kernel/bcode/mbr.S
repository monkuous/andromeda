.code16
.section ".bcode", "ax", @progbits

#define REL(x) (0x600 + ((x) - _start))

.globl _start
.type _start, @function
_start:
    cli
    cld
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $_start, %sp
    mov %sp, %si
    mov $REL(_start), %di
    mov $0x100, %cx
    rep movsw
    ljmp $0, $REL(1f)
1:  sti
    mov $REL(.Lpartitions), %bp
    mov $4, %cx
.Ltry_partition:
    cmpb $0, (%bp)
    js .Lhave_partition
    jne .Linvalid_table
    add $16, %si
    loop .Ltry_partition
    int $0x18
.Lhave_partition:
    cmpb $0x80, (%bp)
    jne .Linvalid_table

    # read vbr
    pushl $0
    pushl 8(%bp)      # use start lba field from partition entry
    pushl $0x07c00000 # 07c0:0000
    pushl $0x00010010 # 1 sector, packet is 16 bytes
    mov $0x42, %ah
    mov %sp, %si
    int $0x13
    jc .Lload_error
    add $16, %sp

    # check for boot signature
    cmpw $0xaa55, (0x7dfe)
    jne .Lmissing_signature

    # start boot sector
    ljmp $0, $0x7c00
.Linvalid_table:
    mov $.Linvalid_table_msg, %si
    jmp .Lpanic
.Lload_error:
    mov $.Lload_error_msg, %si
    jmp .Lpanic
.Lmissing_signature:
    mov $.Lmissing_signature_msg, %si
.Lpanic:
    lodsb
    test %al, %al
    jz .Lhalt
    mov $0xe, %ah
    mov $7, %bx
    int $0x10
    jmp .Lpanic
.Lhalt:
    hlt
    jmp 1b
.size _start, . - _start

.type errors, @object
errors:
.Linvalid_table_msg: .asciz "Invalid partition table"
.Lload_error_msg: .asciz "Error loading operating system"
.Lmissing_signature_msg: .asciz "Missing operating system"
.size errors, . - errors

.org 0x1b8
.type mbr, @object
mbr:
    .long 0 # serial number
    .word 0 # read-only indicator
.Lpartitions:
    .fill 16 * 4, 0, 1
.org 0x1fe
    .word 0xaa55
.size mbr, . - mbr
