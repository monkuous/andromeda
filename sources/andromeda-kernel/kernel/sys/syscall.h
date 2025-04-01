#pragma once

#include "cpu/idt.h"
#include <stddef.h>
#include <stdint.h>

void handle_syscall(idt_frame_t *frame);

int verify_pointer(uintptr_t ptr, size_t size);
