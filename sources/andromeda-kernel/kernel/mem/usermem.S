.text

.globl user_memcpy
.type user_memcpy, @function
user_memcpy:
    push %edi
    push %esi
    mov %eax, %edi
    mov %edx, %esi
    xor %eax, %eax # return value
    rep movsb
    pop %esi
    pop %edi
    ret
.size user_memcpy, . - user_memcpy

.globl user_memset
.type user_memset, @function
user_memset:
    push %edi
    mov %eax, %edi
    mov %edx, %eax
    rep stosb
    pop %edi
    ret
.size user_memset, . - user_memset
