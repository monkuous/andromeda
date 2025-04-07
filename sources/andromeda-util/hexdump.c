#include <ctype.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>

static const char *progname;
static int exit_code = 0;

static unsigned char buffer[16];
static size_t offset;

static void dump_line() {
    static uint64_t position;

    printf("%.8" PRIx64, position);

    for (size_t i = 0; i < sizeof(buffer); i++) {
        if (!(i & 7)) putchar(' ');

        if (i < offset) {
            printf(" %.2x", buffer[i]);
            position++;
        } else {
            printf("   ");
        }
    }

    printf("  |");

    for (size_t i = 0; i < offset; i++) {
        if (isprint(buffer[i])) {
            putchar(buffer[i]);
        } else {
            putchar('.');
        }
    }

    printf("|\n");

    if (position % sizeof(buffer)) printf("%.8" PRIx64 "\n", position);
}

static void dump_file(FILE *file, const char *name) {
    for (;;) {
        size_t avail = sizeof(buffer) - offset;
        size_t count = fread(&buffer[offset], 1, avail, file);

        offset += count;

        if (offset == sizeof(buffer)) {
            dump_line();
            offset = 0;
        }

        if (count < avail) break;
    }

    if (ferror(file)) {
        fprintf(stderr, "%s: %s: %m\n", progname, name);
        exit_code = 1;
    }
}

int main(int argc, char *argv[]) {
    progname = argv[0];
    int opt;

    while ((opt = getopt(argc, argv, "C")) != -1) {
        if (opt == '?') return 2;
    }

    if (optind < argc) {
        for (int i = optind; i < argc; i++) {
            FILE *file = fopen(argv[i], "rb");

            if (!file) {
                fprintf(stderr, "%s: %s: %m\n", argv[0], argv[i]);
                exit_code = 1;
                continue;
            }

            dump_file(file, argv[i]);
        }
    } else {
        dump_file(stdin, "stdin");
    }

    if (offset) dump_line();
    return exit_code;
}
