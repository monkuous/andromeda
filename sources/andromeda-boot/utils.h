#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/stat.h>

extern const char *progname;

static inline FILE *do_open(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file) {
        fprintf(stderr, "%s: failed to open %s: %m\n", progname, path);
        exit(1);
    }
    return file;
}

static inline FILE *maybe_open(const char *path) {
    FILE *file = fopen(path, "r");
    if (!file && errno != ENOENT) {
        fprintf(stderr, "%s: failed to open %s: %m\n", progname, path);
        exit(1);
    }
    return file;
}

static inline const void *mmap_fd(int fd, const char *name, size_t *size_out) {
    struct stat stat;
    if (fstat(fd, &stat)) {
        fprintf(stderr, "%s: %s: stat failed: %m\n", progname, name);
        exit(1);
    }

    void *ptr = mmap(nullptr, (stat.st_size + 0xfff) & ~0xfff, PROT_READ, MAP_PRIVATE, fd, 0);
    if (ptr == MAP_FAILED) {
        fprintf(stderr, "%s: %s: mmap failed: %m\n", progname, name);
        exit(1);
    }

    if (size_out) *size_out = stat.st_size;
    return ptr;
}

static inline const void *mmap_file(const char *path, size_t *size_out) {
    if (!path) {
        if (size_out) *size_out = 0;
        return nullptr;
    }

    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: %s: open failed: %m\n", progname, path);
        exit(1);
    }

    return mmap_fd(fd, path, size_out);
}
