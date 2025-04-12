#include "cpufeat.h"
#include "bootinfo.h"
#include "main.h"
#include "utils.h"
#include <cpuid.h>
#include <stdio.h>

cpufeat_t cpufeat;

void init_cpufeat() {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid(0x80000001, &eax, &ebx, &ecx, &edx) || !(edx & (1u << 29))) {
#if 0
        fprintf(stderr, "%s: cpu does not support 64-bit mode\n", progname);
        exit(1);
#else
        fprintf(stderr,
                "%s: warning: 64-bit mode not supported, but continuing anyway\n",
                progname);
#endif
    }

    cpufeat.nx = edx & (1u << 20);
    cpufeat.direct_1gb = edx & (1u << 26);

    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        cpufeat.pat = edx & (1u << 16);
    }

    if (__get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx)) {
        cpufeat.la57 = ecx & (1u << 16);
    }

    if (cpufeat.nx) kernel_efer_value |= 0x800; /* NXE */
    if (cpufeat.pat) boot_info.flags |= BOOT_INFO_SETUP_PAT;
}
