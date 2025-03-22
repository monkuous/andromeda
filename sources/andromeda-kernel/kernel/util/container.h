#pragma once

#include <stddef.h>

#define container(type, member, value) ((type *)((void *)(value) - offsetof(type, member)))
