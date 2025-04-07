#include <andromeda/cpu.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/ioctl.h>

int main(int, char *argv[]) {
    int fd = open("/dev/cpu", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: failed to open /dev/cpu: %m\n", argv[0]);
        return 1;
    }

    int ret = ioctl(fd, IOCTL_REBOOT);
    if (ret < 0) {
        fprintf(stderr, "%s: ioctl failed: %m\n", argv[0]);
        return 1;
    }
}
