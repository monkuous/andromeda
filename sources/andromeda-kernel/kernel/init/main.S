#include "cpu/gdt.h"
#include "mem/layout.h"

.globl __kern_virt_base
.set __kern_virt_base, KERN_VIRT_BASE

#define PDO(x) (((x) >> 20) & 0xffc)
#define PTO(x) (((x) >> 10) & 0xffc)

#if PDO(KERN_VIRT_BASE) == PDO(PTBL_VIRT_BASE)
#error "Kernel mapping overlaps with recursive mapping"
#endif

#if PTO(PTBL_VIRT_BASE) != 0
#error "Recursive mapping is not aligned to a superpage boundary"
#endif

#define TABLE_FLAGS 0x23
#define WPAGE_FLAGS 0x63

.code16
.section ".text.init", "ax", @progbits

# [in] edx:eax: boot volume lba
# [in] cl: boot drive
.globl _start
.type _start, @function
_start:
    cli
    cld
    xor %bx, %bx
    mov %bx, %ds
    mov %bx, %ss
    mov $_start, %esp
    ljmp $0, $1f
1:  push %cx
    push %edx
    push %eax
    # enter protected mode
    call enable_a20
    pushl $KERN_TO_PHYS(kernel_gdt)
    pushw $.Lgdt_lim
    lgdtl (%esp)
    add $6, %esp
    mov $0x50033, %eax
    mov %eax, %cr0
    ljmp $GDT_SEL_KCODE, $1f
.code32
1:  mov $GDT_SEL_KDATA, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    xor %eax, %eax
    lldt %ax

    # clear bss
    mov $KERN_TO_PHYS(__bss_start), %edi
    mov $KERN_TO_PHYS(__bss_end + 3), %ecx # the +3 is to round up when dividing by 4 later
    sub %edi, %ecx
    shr $2, %ecx
    # eax is already 0
    rep stosl

    # build page directory
    mov $KERN_TO_PHYS(kernel_page_dir), %edi
    mov %edi, %cr3
    or $TABLE_FLAGS, %edi
    mov %edi, (PDO(PTBL_VIRT_BASE) - TABLE_FLAGS)(%edi)

    # build page table
    add $0x1000, %edi
    mov %edi, (-0x1000 - TABLE_FLAGS)(%edi)
    mov %edi, (-0x1000 + PDO(KERN_VIRT_BASE) - TABLE_FLAGS)(%edi)
    mov $(KERN_PHYS_BASE | WPAGE_FLAGS), %eax
.Lmap_single:
    mov %eax, (-TABLE_FLAGS + ((KERN_PHYS_BASE >> 12) * 4))(%edi)
    add $0x1000, %eax
    add $4, %edi
    cmp $KERN_TO_PHYS(_end + WPAGE_FLAGS), %eax
    jb .Lmap_single

    # enable paging
    mov %cr0, %eax
    or $0x80000000, %eax
    mov %eax, %cr0

    # handover to non-init code
    pop %eax
    pop %edx
    pop %cx
    add $KERN_VIRT_BASE, %esp
    xor %ebp, %ebp
    push %ebp
    lgdtl (gdt_desc)
    lidtl (kernel_idt_desc)
    jmp kernel_main
.code16
.size _start, . - _start

# must be called with interrupts disabled
.type enable_a20, @function
enable_a20:
    # check a20 status
    mov $0xffff, %ax
    mov %ax, %es
    mov (.Lcheck_word), %ax
    mov %ax, %dx
    not %dx
    mov %dx, %es:(.Lcheck_word + 0x10)
    mov (.Lcheck_word), %dx
    cmp %ax, %dx
    jne 1f
    ret
1:  # enable a20 using 8042
    call .Lkb_wait
    mov $0xd1, %al
    out %al, $0x64 # command 0xd1: write byte to controller output port
    call .Lkb_wait
    mov $0xdf, %al
    out %al, $0x60 # controller output port 0xdf: enable a20
    call .Lkb_wait
    mov $0xff, %al
    out %al, $0xff # command 0xff: no-op (wait until previous command has been processed)
    call .Lkb_wait
    ret
.Lkb_wait:
    in $0x64, %al
    test $2, %al
    jnz .Lkb_wait
    ret
.Lcheck_word:
    .word 0
.size enable_a20, . - enable_a20

.type do_intcall, @function
do_intcall:
1:  mov $GDT_SEL_BDATA, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    lidtl (bios_idt_desc)
    mov %cr0, %eax
    and $~0x80000001, %eax
    mov %eax, %cr0
    ljmp $0, $1f
1:  xor %ax, %ax
    mov %ax, %ds
    mov %ax, %es
    mov %ax, %fs
    mov %ax, %gs
    mov %ax, %ss
    sti

    # load registers
    popal
    pop %ds
    pop %es
    pop %fs
    pop %gs
    popfl

    # perform interrupt
    .byte 0xcd
.Lvector:
    .byte 0x00

    # save registers
    pushfl
    push %gs
    push %fs
    push %es
    push %ds
    pushal

    # enter protected mode
    cli
    cld
    call enable_a20
    mov $KERN_TO_PHYS(kernel_page_dir), %eax
    mov %eax, %cr3
    lgdtl %cs:(gdt_desc)
    mov $0x80050033, %eax
    mov %eax, %cr0
    ljmpl $GDT_SEL_KCODE, $.Lintcall_ret
.size do_intcall, . - do_intcall

.balign 2
.type gdt_desc, @object
gdt_desc:
    .word .Lgdt_lim
    .long kernel_gdt
.size gdt_desc, . - gdt_desc

.balign 2
.type bios_idt_desc, @object
bios_idt_desc:
    .word 0x3ff
    .long 0
.size bios_idt_desc, . - bios_idt_desc

.code32
.text

.globl intcall
.type intcall, @function
intcall:
    pushfl
    push %ebx
    push %esi
    push %edi
    push %ebp

    # save current page directory
    mov %cr3, %ecx
    push %edx
    push %ecx

    # copy registers to stack
    mov $11, %ecx
    sub $44, %esp
    mov %edx, %esi
    mov %esp, %edi
    rep movsl

    # switch to the right page directory
    mov $KERN_TO_PHYS(kernel_page_dir), %ecx
    mov %ecx, %cr3

    # set target vector, start using identity mappings, and exit protected mode
    mov %al, (.Lvector)
    sub $KERN_VIRT_BASE, %esp
    ljmp $GDT_SEL_BCODE, $do_intcall
.Lintcall_ret:
    mov $GDT_SEL_KDATA, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    xor %eax, %eax
    lldt %ax
    lidt (kernel_idt_desc)

    # clear busy bit and load tss
    andl $~(1 << 9), (kernel_gdt + (GDT_SEL_KTASK & ~3) + 4)
    mov $GDT_SEL_KTASK, %ax
    ltr %ax

    # start using virtual mappings again
    add $KERN_VIRT_BASE, %esp

    # switch back to the original page tables
    mov 44(%esp), %eax
    mov %eax, %cr3

    # copy registers from stack
    mov $11, %ecx
    mov %esp, %esi
    mov 48(%esp), %edi
    rep movsl
    lea 8(%esi), %esp # +8 because cr3 and edi were pushed to the stack before regs

    # return
    pop %ebp
    pop %edi
    pop %esi
    pop %ebx
    popfl
    ret
.size intcall, . - intcall

.data

.balign 8
.globl kernel_gdt
.type kernel_gdt, @object
kernel_gdt:
    .quad 0
    .quad 0xcf9b000000ffff # kernel code
    .quad 0xcf93000000ffff # kernel data
    .quad 0xcffb000000ffff # user code
    .quad 0xcff3000000ffff # user data
    .quad 0xcff3000000ffff # thread data
    .quad 0x009b000000ffff # bios code
    .quad 0x0093000000ffff # bios data
    .quad 0 # kernel tss
    .quad 0 # df tss
.set .Lgdt_lim, . - kernel_gdt - 1
.size kernel_gdt, . - kernel_gdt

.bss

.balign 0x1000
.globl kernel_page_dir
.type kernel_page_dir, @object
kernel_page_dir:
    .space 0x1000 # page directory
    .space 0x1000 # page table
.size kernel_page_dir, . - kernel_page_dir

.section ".note.GNU-stack", "", @progbits
