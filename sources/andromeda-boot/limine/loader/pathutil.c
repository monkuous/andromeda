#include "pathutil.h"
#include "utils.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void do_stat(const char *path, struct stat *buf) {
    if (stat(path, buf)) {
        fprintf(stderr, "%s: %s: stat failed: %m\n", progname, path);
        exit(1);
    }
}

char *get_volume_path(const char *path) {
    char *buf = realpath(path, nullptr);
    if (!buf) {
        fprintf(stderr, "%s: %s: realpath failed: %m\n", progname, path);
        exit(1);
    }

    assert(buf[0] == '/');

    struct stat stat;
    do_stat(path, &stat);
    dev_t device = stat.st_dev;

    char *ptr = strrchr(buf, '/');

    while (ptr != buf) {
        char *orig = ptr;

        do {
            ptr--;
        } while (*ptr != '/');

        char *save = ptr == buf ? ptr + 1 : ptr;
        char saved = *save;
        *save = 0;
        do_stat(buf, &stat);
        *save = saved;

        if (stat.st_dev != device) {
            // This is the last component of the path that resides on a different
            // device than the original path, so the part of the path that comes
            // after this is the volume-relative path.
            return orig;
        }
    }

    return buf;
}
