#include "system.h"
#include "compiler.h"
#include "config.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "string.h"
#include "sys/syscall.h"
#include <errno.h>
#include <sys/utsname.h>

void *hostname;
size_t hostname_len;

ssize_t sys_GETHOSTNAME(uintptr_t buffer, size_t size) {
    int error = -verify_pointer(buffer, size);
    if (unlikely(error)) return error;

    size_t n = size < hostname_len ? size : hostname_len;
    error = -user_memcpy((void *)buffer, hostname, n);
    if (unlikely(error)) return error;

    return n;
}

int sys_SETHOSTNAME(uintptr_t buffer, size_t size) {
    if (current->process->euid) return -EPERM;
    if (size > 0x7fffffff) return -ENAMETOOLONG;

    int error = -verify_pointer(buffer, size);
    if (unlikely(error)) return error;

    void *buf = vmalloc(size);
    error = -user_memcpy(buf, (const void *)buffer, size);
    if (unlikely(error)) return error;

    vmfree(hostname, hostname_len);
    hostname = buf;
    hostname_len = size;

    return 0;
}

int sys_UNAME(uintptr_t buffer) {
    int error = -verify_pointer(buffer, sizeof(struct utsname));
    if (unlikely(error)) return error;

    struct utsname value = {
            .sysname = "Andromeda",
            .release = ANDROMEDA_RELEASE,
            .version = ANDROMEDA_VERSION,
            .machine = "i386",
    };
    memcpy(value.nodename, hostname, hostname_len < sizeof(value.nodename) ? hostname_len : sizeof(value.nodename) - 1);

    return -user_memcpy((void *)buffer, &value, sizeof(value));
}
