#include <andromeda/mount.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *progname;

static void mount_filesystems() {
    FILE *file = fopen("/etc/fstab", "r");
    if (!file) {
        fprintf(stderr, "%s: failed to open fstab: %m\n", progname);
        return;
    }

    char *line = NULL;
    size_t capacity = 0;

    for (;;) {
        ssize_t length = getline(&line, &capacity, file);

        if (length < 0) {
            if (ferror(file)) {
                fprintf(stderr, "%s: failed to read fstab: %m\n", progname);
            }

            break;
        }

        if (length == 0) continue;

        int f1_start = length;
        int f1_end = length;
        int f2_start = length;
        int f2_end = length;

        sscanf(line, " %n%*s%n %n%*s%n", &f1_start, &f1_end, &f2_start, &f2_end);

        if (f1_end == length || line[f1_start] == '#') continue;

        line[f1_end] = 0;
        line[f2_end] = 0;

        const char *src = &line[f1_start];
        const char *mountpoint = &line[f2_start];

        if (mount(AT_FDCWD, strcmp(src, "<none>") ? src : NULL, AT_FDCWD, mountpoint)) {
            fprintf(stderr, "%s: failed to mount %s at %s: %m\n", progname, src, mountpoint);
        }
    }

    free(line);
    fclose(file);
}

int main(int, char *argv[]) {
    progname = argv[0];

    if (getpid() != 1) {
        fprintf(stderr, "%s: not running with PID 1\n", argv[0]);
        return EXIT_FAILURE;
    }

    mount_filesystems();

    char *args[] = {"/sbin/bash", "--login", nullptr};
    execve("/sbin/bash", args, environ);
    fprintf(stderr, "%s: failed to start bash: %m\n", argv[0]);
    return EXIT_FAILURE;
}
