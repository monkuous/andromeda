#include <stdio.h>
#include <unistd.h>

int main(int, char *argv[]) {
    char *args[] = {"/sbin/bash", "--login", nullptr};
    execve("/sbin/bash", args, environ);
    fprintf(stderr, "%s: failed to start bash: %m\n", argv[0]);
    return 127;
}
