#include <andromeda/mount.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int, char *argv[]) {
    if (mount(AT_FDCWD, nullptr, AT_FDCWD, "/tmp")) {
        fprintf(stderr, "%s: failed to mount /tmp: %m\n", argv[0]);
        return EXIT_FAILURE;
    }

    char *args[] = {"/sbin/bash", "--login", nullptr};
    execve("/sbin/bash", args, environ);
    fprintf(stderr, "%s: failed to start bash: %m\n", argv[0]);
    return EXIT_FAILURE;
}
