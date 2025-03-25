.text

.type idt_entry, @function
idt_entry:
    pushw %gs
    pushw %fs
    pushw %es
    pushw %ds
    pushal

    mov %ss, %eax
    mov %eax, %ds
    mov %eax, %es
    mov %eax, %fs
    mov %eax, %gs

    xor %ebp, %ebp
    mov %esp, %eax
    and $~15, %esp
    call idt_dispatch
    mov %eax, %esp

    popal
    popw %ds
    popw %es
    popw %fs
    popw %gs
    add $8, %esp
    iret
.size idt_entry, . - idt_entry

.macro idt_thunk vec, errc=0
1:
.if \errc == 0
    pushl $0
.endif
    pushl $\vec
    jmp idt_entry
.pushsection ".rodata.idt_thunks", "a", @progbits
.org \vec * 4
    .long 1b
.popsection
.endm

.pushsection ".rodata.idt_thunks", "a", @progbits
.balign 4
.globl idt_thunks
.type idt_thunks, @object
idt_thunks:
.popsection

.type idt_thunk_code, @function
idt_thunk_code:

idt_thunk 0x00 # #DE: SIGFPE
idt_thunk 0x01 # #DB: SIGTRAP
idt_thunk 0x02 # NMI
idt_thunk 0x03 # #BP: SIGTRAP
# 0x04 (#OF) is SIGSEGV via #GP
# 0x05 (#BR) is SIGSEGV via #GP
idt_thunk 0x06 # #UD: SIGILL
# 0x07 (#NM) will never occur
# 0x08 (#DF) is handled by a task gate
# 0x09 does not exist
idt_thunk 0x0a, errc=1 # #TS: SIGSEGV (can't be done via #GP, would trigger #DF)
idt_thunk 0x0b, errc=1 # #NP: SIGSEGV (can't be done via #GP, would trigger #DF)
idt_thunk 0x0c, errc=1 # #SS: SIGSEGV (can't be done via #GP, would trigger #DF)
idt_thunk 0x0d, errc=1 # #GP: SIGSEGV
idt_thunk 0x0e, errc=1 # #PF: SIGSEGV (can't be done via #GP, sometimes handled transparently)
# 0x0f does not exist
idt_thunk 0x10 # #MF: SIGFPE
# 0x11 (#AC) is SIGSEGV via #GP
# 0x12 (#MC) will never occur
idt_thunk 0x13 # #XM: SIGFPE
# 0x14 (#VE) will never occur
# 0x15 (#CP) will never occur
# 0x16 does not exist
# 0x17 does not exist
# 0x18 does not exist
# 0x19 does not exist
# 0x1a does not exist
# 0x1b does not exist
# 0x1c does not exist
# 0x1d does not exist
# 0x1e does not exist
# 0x1f does not exist
idt_thunk 0x20 # syscall

.size idt_thunk_code, . - idt_thunk_code

.pushsection ".rodata.idt_thunks", "a", @progbits
.org 0x21 * 4
.size idt_thunks, . - idt_thunks
.popsection

.section ".note.GNU-stack", "", @progbits
