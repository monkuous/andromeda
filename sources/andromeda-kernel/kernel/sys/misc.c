#include "misc.h"
#include "compiler.h"
#include "mem/usermem.h"
#include "sys/syscall.h"
#include "util/print.h"
#include <stdint.h>

int sys_KLOG(uintptr_t str, size_t len) {
    int error = -verify_pointer(str, len);
    if (unlikely(error)) return error;

    unsigned char buffer[1024];

    while (len) {
        size_t cur = len < sizeof(buffer) ? len : sizeof(buffer);
        int error = -user_memcpy(buffer, (const void *)str, cur);
        if (unlikely(error)) return error;

        printk(cur == len ? "%S\n" : "%S", buffer, cur);

        str += cur;
        len -= cur;
    }

    return 0;
}
