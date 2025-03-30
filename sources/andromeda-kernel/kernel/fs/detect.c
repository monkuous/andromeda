#include "detect.h"
#include "fs/fat.h"
#include "util/print.h"
#include <errno.h>

int fsdetect(fs_t **out, void *ctx) {
    if (!fat_create(out, ctx)) return 0;

    printk("fsdetect: unrecognized filesystem\n");
    return EINVAL;
}
