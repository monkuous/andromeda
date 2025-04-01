#pragma once

#include <stdint.h>

static inline uint32_t read_cr0() {
    uint32_t value;
    asm volatile("mov %%cr0, %0" : "=r"(value));
    return value;
}

static inline uint32_t read_cr2() {
    uint32_t value;
    asm volatile("mov %%cr2, %0" : "=r"(value));
    return value;
}

static inline uint32_t read_cr3() {
    uint32_t value;
    asm volatile("mov %%cr3, %0" : "=r"(value));
    return value;
}

static inline void write_cr3(uint32_t value) {
    asm("mov %0, %%cr3" ::"r"(value) : "memory");
}
