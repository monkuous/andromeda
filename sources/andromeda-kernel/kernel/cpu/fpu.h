#pragma once

#include <signal.h> /* IWYU pragma: keep */

typedef struct {
    alignas(16) unsigned char data[512];
} fpu_area_t;

void init_fpu();
void fpu_save(fpu_area_t *area);
void fpu_restore(fpu_area_t *area);

void fpu_save_signal(struct _fpstate *area);
void fpu_restore_signal(struct _fpstate *area);
void fpu_signal_abort(struct _fpstate *area);
