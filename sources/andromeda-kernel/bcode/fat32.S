#define BPREL(x) ((x) - _start)(%bp)
#define LOAD_ADDR 0x8000

.code16
.section ".bcode", "ax", @progbits

.globl _start
.type _start, @function
_start:
    # manually encoded to ensure it's the right encoding
    .byte 0xeb, real_start - . - 1
    .byte 0x90
.size _start, . - _start

.type bpb, @object
bpb:
.Ldata_sector:  .long 0
.Lfat_sector:   .long 0
.Lsector_size:  .word 0
.Lcluster_size: .byte 0
.Lnum_reserved: .word 0
.Lnum_fats:     .byte 0
                .space 11
.Lvol_offset:   .long 0
                .space 4
.Lfat_size:     .long 0
.Lfs_flags:     .word 0
                .space 2
.Lroot_cluster: .long 0
                .space 2
.Lbackup_sect:  .word 0
                .space 12
.Ldrive_number: .byte 0
                .space 25
.org 0x5a
.size bpb, . - bpb

.type real_start, @function
real_start:
    cli
    cld
    xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %ss
    mov $_start, %sp
    mov %sp, %bp
    ljmp $0, $1f
1:  sti
    mov %dl, BPREL(.Ldrive_number)
    # determine lba for fat and data regions
    movzbl BPREL(.Lnum_fats), %eax
    mull BPREL(.Lfat_size)
    movzwl BPREL(.Lnum_reserved), %edx
    mov %edx, BPREL(.Lfat_sector)
    add %eax, %edx
    mov %edx, BPREL(.Ldata_sector)
    # adjust fat sector to active fat
    movzwl BPREL(.Lfs_flags), %eax
    test $0x80, %al
    jz .Lhave_fat_sector
    and $15, %eax
    mull BPREL(.Lfat_size)
    add %eax, BPREL(.Lfat_sector)
.Lhave_fat_sector:
    # find directory entry for kernel
    mov BPREL(.Lroot_cluster), %eax
.Ltry_cluster:
    push %eax
    mov $LOAD_ADDR, %ebx
    mov %bx, %di
    call read_cluster
    pop %eax
.Ltry_entry:
    mov $filename, %si
    mov $11, %cx
    repe cmpsb
    je .Lhave_entry

    add %cx, %di
    add $(0x20 - 11), %di
    cmp %bx, %di
    jb .Ltry_entry
    call next_cluster
    jc .Ltry_cluster
    jmp panic
.Lhave_entry:
    # load file
    mov (18 - 11)(%di), %eax # load high part of cluster number
    mov (26 - 11)(%di), %ax # load low part of cluster number
    mov $LOAD_ADDR, %ebx
.Lsingle_cluster:
    push %eax
    call read_cluster
    pop %eax
    call next_cluster
    jc .Lsingle_cluster
    # start kernel image
    mov BPREL(.Lvol_offset), %eax
    xor %edx, %edx
    mov BPREL(.Ldrive_number), %cl
    jmp LOAD_ADDR
.size real_start, . - real_start

.type panic, @function
panic:
    mov $err_msg, %si
    mov $.Lerr_len, %cx
1:  lodsb
    mov $0xe, %ah
    mov $7, %bx
    int $0x10
    loop 1b
    sti
1:  hlt
    jmp 1b
.size panic, . - panic

# [in] eax: cluster number
# [inout] ebx: destination
# clobber: eax, edx, ecx, esi
.type read_cluster, @function
read_cluster:
    movzbl BPREL(.Lcluster_size), %ecx
    sub $2, %eax
    mul %ecx
    add BPREL(.Ldata_sector), %eax
    # fall through to read_sectors
.size read_cluster, . - read_cluster

# [in] eax: volume-relative sector
# [inout] ebx: destination
# [in] cx: number of sectors
# clobber: eax, edx, cx, esi
.type read_sectors, @function
read_sectors:
    # make it absolute
    xor %edx, %edx
    add BPREL(.Lvol_offset), %eax
    adc %edx, %edx

.Lsingle_read:
    # limit sector count
    mov $127, %si
    cmp %cx, %si
    jbe .Lcount_ok
    mov %cx, %si
.Lcount_ok:

    # create dap
    push %edx
    push %eax
    mov %ebx, %eax
    shl $12, %eax
    shr $12, %ax
    push %eax
    push %si
    pushw $0x10

    # perform read call
    mov $0x42, %ah
    mov BPREL(.Ldrive_number), %dl
    mov %sp, %si
    int $0x13
    jc panic

    pop %si # discard packet size
    pop %si # restore sector count

    # advance destination address
    movzwl BPREL(.Lsector_size), %eax
    movzwl %si, %esi
    mull %esi
    add %eax, %ebx

    pop %eax # discard destination address
    pop %eax # restore low part of lba
    pop %edx # restore high part of lba

    # advance lba
    add %esi, %eax
    adc $0, %edx

    sub %si, %cx
    jnz .Lsingle_read
    ret
.size read_sectors, . - read_sectors

# [inout] eax: cluster number
# [in] ebx: buffer address
# [out] eflags.cf: clear if eof
# clobber: eax, edx, ecx, esi, edi
.type next_cluster, @function
next_cluster:
    # calculate sector lba and in-sector offset
    movzwl BPREL(.Lsector_size), %ecx
    shl $2, %eax
    xor %edx, %edx
    div %ecx
    add BPREL(.Lfat_sector), %eax
    mov %edx, %edi
    # read sector
    push %ebx
    mov $1, %cx
    call read_sectors
    pop %ebx
    # get cluster number and return
    add %ebx, %edi
    mov %di, %si
    shr $4, %edi
    and $15, %si
    mov %di, %es
    mov %es:(%si), %eax
    cmp $0xffffff8, %eax
    ret
.size next_cluster, . - next_cluster

.type err_msg, @object
err_msg: .ascii "Load failed\r\n"
.set .Lerr_len, . - err_msg
.size err_msg, . - err_msg

.type filename, @object
filename: .ascii "ANDROMEDSYS"
.size filename, . - filename

.org 0x1fe
.word 0xaa55
