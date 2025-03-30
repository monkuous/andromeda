#include "detect.h"
#include "drv/device.h"
#include "fs/fat.h"
#include "fs/iso9660.h"
#include "util/print.h"
#include <errno.h>

int fsdetect(fs_t **out, void *ctx) {
    bdev_t *dev = ctx;
    if (dev->fs) return EBUSY;

    if (!fat_create(out, ctx)) return 0;
    if (!iso9660_create(out, ctx)) return 0;

    printk("fsdetect: unrecognized filesystem\n");
    return EINVAL;
}
