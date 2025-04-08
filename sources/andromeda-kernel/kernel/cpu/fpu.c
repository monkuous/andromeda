#include "fpu.h"
#include "asm/cr.h"
#include "string.h"
#include <cpuid.h>
#include <stdint.h>

static bool have_fxsave;

void init_fpu() {
    uint32_t eax, ebx, ecx, edx;
    if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
        if (edx & (1ul << 24)) {
            have_fxsave = true;
            write_cr4(read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT);
        }
    }
}

void fpu_save(fpu_area_t *area) {
    if (have_fxsave) {
        asm("fxsave %0" : "=m"(*area));
    } else {
        asm("fsave %0" : "=m"(*area));
    }
}

void fpu_restore(fpu_area_t *area) {
    if (have_fxsave) {
        asm("fxrstor %0" ::"m"(*area));
    } else {
        asm("frstor %0" ::"m"(*area));
    }
}

void fpu_save_signal(struct _fpstate *area) {
    fpu_area_t real_area = {};
    fpu_save(&real_area);

    if (have_fxsave) {
        memcpy(&area->_fxsr_env, &real_area, 512);

        area->cw = area->_fxsr_env[0];
        area->sw = area->_fxsr_env[0] >> 16;
        area->tag = 0;

        for (int i = 0; i < 8; i++) {
            if (area->_fxsr_env[1] & (1ul << i)) {
                area->tag |= 3ul << (i * 2);
            }
        }

        area->ipoff = area->_fxsr_env[2];
        area->cssel = (area->_fxsr_env[3] & 0xffff) | (area->_fxsr_env[1] & 0xffff0000);
        area->dataoff = area->_fxsr_env[4];
        area->datasel = area->_fxsr_env[5];
    } else {
        memcpy(area, &real_area, 112);
    }
}

void fpu_restore_signal(struct _fpstate *area) {
    fpu_area_t real_area;

    if (have_fxsave) {
        memcpy(&real_area, &area->_fxsr_env, 512);
    } else {
        memcpy(&real_area, area, 112);
    }

    fpu_restore(&real_area);
}

void fpu_signal_abort(struct _fpstate *area) {
    if (!have_fxsave) fpu_restore_signal(area);
}
