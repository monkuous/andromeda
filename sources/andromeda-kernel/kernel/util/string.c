#include <stddef.h>
#include <stdint.h>

int memcmp(const void *s1, const void *s2, size_t n) {
    const unsigned char *b1 = s1;
    const unsigned char *b2 = s2;

    while (n--) {
        unsigned char c1 = *b1++;
        unsigned char c2 = *b2++;

        if (c1 < c2) return -1;
        if (c1 > c2) return 1;
    }

    return 0;
}

void *memcpy(void *restrict s1, const void *restrict s2, size_t n) {
    unsigned char *c1 = s1;
    const unsigned char *c2 = s2;

    while (n--) {
        *c1++ = *c2++;
    }

    return s1;
}

void *memmove(void *s1, const void *s2, size_t n) {
    unsigned char *c1 = s1;
    const unsigned char *c2 = s2;

    if ((uintptr_t)c1 < (uintptr_t)c2) {
        while (n--) {
            *c1++ = *c2++;
        }
    } else if ((uintptr_t)c1 > (uintptr_t)c2) {
        c1 += n;
        c2 += n;

        while (n--) {
            *--c1 = *--c2;
        }
    }

    return s1;
}

void *memset(void *s, int c, size_t n) {
    unsigned char *ptr = s;
    unsigned char fill = c;

    while (n--) {
        *ptr++ = fill;
    }

    return s;
}
