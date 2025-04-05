#include "mem/layout.h"

#define PHYS(x) ((x) - KERN_VIRT_BASE)

.text

.globl cpu_set_registers
.type cpu_set_registers, @function
cpu_set_registers:
    # copy regs to stack
    mov %eax, %esi
    mov $76, %ecx
    sub %ecx, %esp
    mov %esp, %edi
    rep movsb

    # disable paging
    mov $PHYS(kernel_page_dir), %eax
    mov %eax, %cr3
    jmp do_set_registers
.size cpu_set_registers, . - cpu_set_registers

.section ".text.phys", "ax", @progbits

.type do_set_registers, @function
do_set_registers:
    mov $0x11, %eax
    mov %eax, %cr0
    xor %eax, %eax
    mov %eax, %cr2
    mov %eax, %cr3
    sub $KERN_VIRT_BASE, %esp

    # load new gdt
    lgdtl 70(%esp)

    # set jump target
    mov 60(%esp), %eax
    mov %eax, (.Ljmp_target)
    mov 64(%esp), %eax
    mov %eax, (.Ljmp_target + 4)

    # set the registers
    popl %eax
    lldt %ax
    popl %eax
    popl %ebx
    popl %ecx
    popl %edx
    popl %esi
    popl %edi
    popl %ebp
    popfl
    popl %ds
    popl %es
    popl %fs
    popl %gs
    popl %ss
    mov %cs:(%esp), %esp
    ljmpl *%cs:(.Ljmp_target)
.Ljmp_target:
    .long 0, 0
.size do_set_registers, . - do_set_registers

.section ".note.GNU-stack", "", @progbits
