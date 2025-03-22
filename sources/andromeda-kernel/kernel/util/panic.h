#pragma once

#include "compiler.h"

[[noreturn]] void panic(const char *format, ...);

#ifndef NDEBUG
#define ASSERT(x)                                                                                                      \
    (likely(x) ? (void)0 : panic("assertion failed: `%s` in %s at %s:%d", #x, __func__, __FILE__, __LINE__))
#else
#define ASSERT(x) ((void)0)
#endif

#define UNREACHABLE()                                                                                                  \
    ({                                                                                                                 \
        ASSERT(!"unreachable");                                                                                        \
        __builtin_unreachable();                                                                                       \
    })
