.section ".text._start", "ax", @progbits

# inputs:
#  eax: low 32 bits of value that should be written to efer
#  ebx: value that should be written to cr4
#  ecx: value that should be written to cr3
#  edx: high 32 bits of value that should be written to efer
#  esi: pointer to boot info structure
#  esp: top of kernel stack (aligned to 16 bytes)
.globl _start
.type _start, @function
_start:
    mov %ebx, %cr4
    mov %ecx, %cr3
    mov $0xc0000080, %ecx
    wrmsr
    mov $0x80010011, %eax
    mov %eax, %cr0

    # figure out where we are
    call 1f
1:  pop %ebx
    add $(_GLOBAL_OFFSET_TABLE_ - 1b), %ebx

    # clear bss
    lea __bss_start@GOTOFF(%ebx), %edi
    xor %eax, %eax
    mov $__bss_size4, %ecx
    rep stosl

    # relocate ourselves
    lea _DYNAMIC@GOTOFF(%ebx), %edi
.Lexamine_dynamic_entry:
    mov (%edi), %eax
    test %eax, %eax
    jz .Ldynamic_done

    cmp $18, %eax # DT_RELSZ
    jb .Ltry_dt_rel
    ja .Ltry_dt_relent
    mov 4(%edi), %edx
    jmp .Ldynamic_next
.Ltry_dt_rel:
    cmp $17, %eax # DT_REL
    jne .Ldynamic_next
    mov 4(%edi), %ebp
    jmp .Ldynamic_next
.Ltry_dt_relent:
    cmp $19, %eax # DT_RELENT
    jne .Ldynamic_next
    mov 4(%edi), %ecx
.Ldynamic_next:
    add $8, %edi
    jmp .Lexamine_dynamic_entry

.Ldynamic_done:
    test %edx, %edx
    jz .Lrelocations_done

    # determine the base value, which is the offset the prekernel was loaded with
    lea _DYNAMIC@GOTOFF(%ebx), %edi
    sub _GLOBAL_OFFSET_TABLE_@GOTOFF(%ebx), %edi # GOT[0] holds the link-time address of _DYNAMIC

    add %edi, %ebp
.Ldo_relocation:
    cmpb $8, 4(%ebp) # R_386_RELATIVE
    jne .Lthis_reloc_done

    # perform relocation: *(uint32_t *)addr += base
    mov (%ebp), %eax
    add %edi, %eax
    add %edi, (%eax)

.Lthis_reloc_done:
    add %ecx, %ebp
    sub %ecx, %edx
    jnz .Ldo_relocation
.Lrelocations_done:

    # run prekernel
    mov %esi, %eax
    call run_prekernel

    # prepare stack for the return instruction that does handover
    xor %ecx, %ecx
    pushl %ecx # dummy return address for kernel entrypoint, high 32 bits
    pushl %ecx # dummy return address for kernel entrypoint, low 32 bits
    pushl %edx # kernel entrypoint, high 32 bits
    pushl %eax # kernel entrypoint, low 32 bits

    # jump to 64 bit mode
    lea .Ldo_handover@GOTOFF(%ebx), %eax
    pushl $0x28
    pushl %eax
    lretl
.code64
.Ldo_handover:
    mov $0x30, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs
    mov %eax, %ss
    xor %eax, %eax
    lldt %ax

    # transition to using addresses in the hhdm
    mov hhdm_offset(%rip), %rbx
    lea 1f(%rip), %rax
    add %rbx, %rax
    push %rax
    ret
1:  add %rbx, %rsp
    sub $16, %rsp
    sgdt (%rsp)
    add %rbx, 2(%rsp)
    lgdt (%rsp)
    add $16, %rsp

    # unmap lower half of address space
    mov %cr3, %rdi
    add %rbx, %rdi
    xor %eax, %eax
    mov $256, %ecx
    rep stosq

    # flush tlb
    mov %cr3, %rax
    mov %rax, %cr3

    # zero all registers and jump to kernel entry point
    xor %eax, %eax
    xor %ebx, %ebx
    xor %ecx, %ecx
    xor %edx, %edx
    xor %esi, %esi
    xor %edi, %edi
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
.code32
.size _start, . - _start

.section ".note.GNU-stack", "", @progbits
