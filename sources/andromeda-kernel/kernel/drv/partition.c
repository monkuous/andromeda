#include "partition.h"
#include "compiler.h"
#include "fs/pgcache.h"
#include "fs/vfs.h"
#include "mem/vmalloc.h"
#include "util/panic.h"
#include "util/print.h"

typedef struct [[gnu::packed]] {
    uint8_t attr;
    uint8_t chs0[3];
    uint8_t type;
    uint8_t chs1[3];
    uint32_t lba0;
    uint32_t nlba;
} mbr_partition_t;

typedef struct [[gnu::packed]] {
    uint32_t serial;
    uint16_t ro_indicator;
    mbr_partition_t partitions[4];
    uint16_t signature;
} mbr_t;

typedef int (*discover_func_t)(bdev_t *, const void *, size_t, part_cb_t, void *);

static int chs_to_linear(uint8_t chs[3]) {
    unsigned cyl = ((chs[1] & 0xc0) << 2) | chs[2];
    unsigned head = chs[0];
    unsigned sec = chs[1] & 0x3f;

    if (!sec) return -1;

    return (cyl << 14) | (head << 6) | sec;
}

static int discover_mbr(bdev_t *bdev, const void *name, size_t length, part_cb_t cb, void *ctx) {
    mbr_t mbr;
    int error = pgcache_read(&bdev->data, &mbr, sizeof(mbr), 0x200 - sizeof(mbr));
    if (unlikely(error)) return -error;

    // verify that this is an mbr volume
    if (mbr.signature != 0xaa55) return 0;

    bool have_active = false;

    for (int i = 0; i < 4; i++) {
        mbr_partition_t *partition = &mbr.partitions[i];

        if (partition->attr != 0) {
            if (have_active || partition->attr != 0x80) return 0;
            have_active = true;
        }

        if (!partition->type) continue;

        int chs0 = chs_to_linear(partition->chs0);
        int chs1 = chs_to_linear(partition->chs1);

        if (chs0 < 0 || chs1 < 0) return 0;
        if (chs0 > chs1) return 0;

        if (!partition->nlba) return 0;
    }

    // create id-based symlink
    unsigned char link_path[32];
    size_t link_length = snprintk(link_path, sizeof(link_path), "/dev/volumes/%8x", mbr.serial);
    ASSERT(link_length <= sizeof(link_path));

    char *target;
    size_t targ_len = asprintk(&target, "../%S", name, length);
    error = vfs_symlink(nullptr, link_path, link_length, target, targ_len);
    vmfree(target, targ_len);
    if (unlikely(error)) return -error;

    unsigned char *id = &link_path[13];
    size_t id_length = link_length - 13;

    for (int i = 0; i < 4; i++) {
        mbr_partition_t *partition = &mbr.partitions[i];
        if (!partition->type) continue;

        unsigned char cur_id[16];
        size_t cur_id_length = snprintk(cur_id, sizeof(cur_id), "%S-%d", id, id_length, i);
        ASSERT(cur_id_length <= sizeof(cur_id));

        cb(partition->lba0, partition->nlba, cur_id, cur_id_length, ctx);
    }

    return 1;
}

static discover_func_t discover_funcs[] = {
        discover_mbr,
};

int discover_partitions(bdev_t *bdev, const void *name, size_t length, part_cb_t cb, void *ctx) {
    for (size_t i = 0; i < sizeof(discover_funcs) / sizeof(*discover_funcs); i++) {
        int ret = discover_funcs[i](bdev, name, length, cb, ctx);
        if (unlikely(ret < 0)) return ret;
        if (ret) break;
    }

    return 0;
}
