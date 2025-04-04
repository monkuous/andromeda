#include <andromeda/mount.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s MOUNTPOINT...\n", argv[0]);
        return 2;
    }

    int status = EXIT_SUCCESS;

    for (int i = 1; i < argc; i++) {
        if (umount(AT_FDCWD, argv[i])) {
            fprintf(stderr, "%s: %s: %m\n", argv[0], argv[i]);
            status = EXIT_FAILURE;
        }
    }

    return status;
}
