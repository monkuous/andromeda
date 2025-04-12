#pragma once

#include <stdint.h>

static inline uint64_t rdmsr(uint32_t msr) {
    uint64_t value;
    asm volatile("rdmsr" : "=A"(value) : "c"(msr));
    return value;
}

static inline void wrmsr(uint32_t msr, uint64_t value) {
    asm("wrmsr" ::"c"(msr), "A"(value));
}

static inline void outb(uint16_t port, uint8_t value) {
    asm("outb %0, %1" ::"a"(value), "Nd"(port));
}

static inline void mmio_write32(void *ptr, uint32_t value) {
    asm volatile("mov %1, %0" : "=m"(*(volatile uint32_t *)ptr) : "a"(value));
}

static inline uint32_t mmio_read32(void *ptr) {
    uint32_t value;
    asm volatile("mov %1, %0" : "=a"(value) : "m"(*(volatile uint32_t *)ptr));
    return value;
}

static inline void tsc_delay(uint64_t ticks) {
    uint64_t end = __builtin_ia32_rdtsc() + ticks;
    while (__builtin_ia32_rdtsc() < end) asm("");
}
