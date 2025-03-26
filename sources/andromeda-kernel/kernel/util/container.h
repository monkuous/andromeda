#pragma once

#include <stddef.h>

#define container(type, member, value)                                                                                 \
    ({                                                                                                                 \
        __typeof__(value) _v = (value);                                                                                \
        _v ? (type *)((void *)_v - offsetof(type, member)) : nullptr;                                                  \
    })
