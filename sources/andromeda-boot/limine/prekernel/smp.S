.code16
.text

#define REL(x) ((x) - smp_trampoline_start)

.globl smp_trampoline_start, smp_trampoline_data, smp_trampoline_end
smp_trampoline_start:
    mov %cs:REL(.Ljmp_target), %ebx
    lgdtl %cs:REL(.Lgdtr)
    mov %cs:REL(.Lcr4), %eax
    mov %eax, %cr4
    mov %cs:REL(.Lcr3), %eax
    mov %eax, %cr3
    mov %cs:REL(.Lefer), %eax
    mov %cs:REL(.Lefer + 4), %edx
    mov $0xc0000080, %ecx
    wrmsr
    mov $0x00010011, %eax
    mov %eax, %cr0
    ljmpl *%cs:REL(.Ljmp_target)
.code32
.Lstart32:
    mov $0x20, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    add $(_GLOBAL_OFFSET_TABLE_ - .Lstart32), %ebx # ebx now contains GOT base

    # set up apic and read our own id
    mov $0x1b, %ecx
    rdmsr
    cmpb $0, smp_using_x2apic@GOTOFF(%ebx)
    je .Lget_id_xapic

    # enable x2apic and get id
    or $0x400, %eax
    wrmsr
    mov $0x802, %ecx
    rdmsr
    jmp .Lhave_id

.Lget_id_xapic:
    and $0xfffff000, %eax
    mov 0x20(%eax), %eax
    shr $24, %eax
.Lhave_id:

    # stop initialization if we were too late
    mov $-1, %ecx
    lock xchg %ecx, smp_current_id@GOTOFF(%ebx)
    cmp %eax, %ecx
    je .Linit_ok
1:  hlt
    jmp 1b
.Linit_ok:

    # get a stack from the bsp
1:  mov smp_stack@GOTOFF(%ebx), %esp
    test %esp, %esp
    jz 1b

    # enable paging and long mode
    mov %cr0, %eax
    or $0x80000000, %eax
    mov %eax, %cr0

    # jump to 64 bit mode
    lea .Lstart64@GOTOFF(%ebx), %eax
    pushl $0x28
    pushl %eax
    lretl
.code64
.Lstart64:
    mov $0x30, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    xor %eax, %eax
    lldt %ax

    # use hhdm addresses instead of physical ones
    mov hhdm_offset(%rip), %rdx
    lea 1f(%rip), %rax
    add %rdx, %rax
    jmp *%rax
1:  add %rdx, %rsp
    sub $16, %rsp
    sgdt (%rsp)
    add %rdx, 2(%rsp)
    lgdt (%rsp)
    add $16, %rsp

    # finish initialization
    mov smp_info(%rip), %rdi
    movb $1, smp_ready(%rip) # tell the bsp that we're done

    # wait for goto_address to be set
1:  mov 16(%rdi), %rax
    test %rax, %rax
    jz 1b

    # start the kernel
    pushq $0
    popfq
    pushq $0
    pushq %rax

    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %esi, %esi
    # don't zero edi, that contains the mp info structure
    xor %ebp, %ebp
    xor %r8d, %r8d
    xor %r9d, %r9d
    xor %r10d, %r10d
    xor %r11d, %r11d
    xor %r12d, %r12d
    xor %r13d, %r13d
    xor %r14d, %r14d
    xor %r15d, %r15d
    ret

.balign 4
smp_trampoline_data:
.Lcr3: .long 0
.Lcr4: .long 0
.Lefer: .quad 0
.Ljmp_target: .long REL(.Lstart32), 0x18
.Lgdtr: .word 0, 0, 0
smp_trampoline_end:

.section ".note.GNU-stack", "", @progbits
