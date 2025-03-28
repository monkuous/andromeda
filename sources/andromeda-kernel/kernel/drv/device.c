#include "device.h"
#include <errno.h>

int open_bdev(dev_t, file_t *, int) {
    return ENXIO;
}

int open_cdev(dev_t, file_t *, int) {
    return ENXIO;
}
