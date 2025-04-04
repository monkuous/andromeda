#include <andromeda/mount.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char *argv[]) {
    int res;

    switch (argc) {
    case 2: res = mount(AT_FDCWD, nullptr, AT_FDCWD, argv[1]); break;
    case 3:
        if (strlen(argv[1])) {
            res = mount(AT_FDCWD, argv[1], AT_FDCWD, argv[2]);
        } else {
            errno = EINVAL;
            res = -1;
        }
        break;
    default: fprintf(stderr, "usage: %s [SOURCE] MOUNTPOINT\n", argv[0]); return 2;
    }

    if (res) {
        fprintf(stderr, "%s: mount failed: %m\n", argv[0]);
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
