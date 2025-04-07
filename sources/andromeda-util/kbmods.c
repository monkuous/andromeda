#include <andromeda/ioctl.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define BOTH_SHIFTS (MODIFIER_LEFT_SHIFT | MODIFIER_RIGHT_SHIFT)

int main(int argc, char *argv[]) {
    int c;
    int modifiers = 0;
    bool allow_either_shift = false;

    while ((c = getopt(argc, argv, "hcalrsCNSI")) != -1) {
        switch (c) {
        case '?': return 2;
        case 'h':
            printf("usage: %s [OPTION...]\n"
                   "\n"
                   "options:\n"
                   "  -h       show this help message\n"
                   "  -c       fail if the control key isn't pressed\n"
                   "  -a       fail if the alt key isn't pressed\n"
                   "  -l       fail if the left shift key isn't pressed\n"
                   "  -r       fail if the right shift key isn't pressed\n"
                   "  -s       fail if neither shift keys are pressed (overrides -l and -r)\n"
                   "  -C       fail if caps lock isn't enabled\n"
                   "  -N       fail if num lock isn't enabled\n"
                   "  -S       fail if scroll lock isn't enabled\n"
                   "  -I       fail if insert isn't enabled\n",
                   argv[0]);
            return 0;
        case 'c': modifiers |= MODIFIER_CONTROL; break;
        case 'a': modifiers |= MODIFIER_ALT; break;
        case 'l': modifiers |= MODIFIER_LEFT_SHIFT; break;
        case 'r': modifiers |= MODIFIER_RIGHT_SHIFT; break;
        case 's': modifiers |= BOTH_SHIFTS; allow_either_shift = true; break;
        case 'C': modifiers |= MODIFIER_CAPS_LOCK; break;
        case 'N': modifiers |= MODIFIER_NUM_LOCK; break;
        case 'S': modifiers |= MODIFIER_SCROLL_LOCK; break;
        case 'I': modifiers |= MODIFIER_INSERT; break;
        }
    }

    int fd = open("/dev/tty", O_RDONLY);
    if (fd < 0) {
        fprintf(stderr, "%s: failed to open /dev/tty: %m\n", argv[0]);
        return -1;
    }

    int active = ioctl(fd, IOCTL_GET_MODIFIER_STATE);
    if (active < 0) {
        fprintf(stderr, "%s: failed to get modifier state: %m\n", argv[0]);
        return -1;
    }

    if (allow_either_shift && (active & BOTH_SHIFTS)) active |= BOTH_SHIFTS;

    return (active & modifiers) != modifiers;
}
