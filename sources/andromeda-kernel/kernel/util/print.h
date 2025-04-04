#pragma once

#include <stdarg.h>
#include <stddef.h>

void print_set_console(bool console);

void vprintk(const char *format, va_list args);
void printk(const char *format, ...);

size_t vsnprintk(void *buffer, size_t size, const char *format, va_list args);
size_t snprintk(void *buffer, size_t size, const char *format, ...);

size_t vasprintk(char **output, const char *format, va_list args);
size_t asprintk(char **output, const char *format, ...);
