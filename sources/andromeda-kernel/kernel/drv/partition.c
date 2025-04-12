#include "partition.h"
#include "compiler.h"
#include "fs/pgcache.h"
#include "fs/vfs.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/panic.h"
#include "util/print.h"
#include <stdint.h>

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

typedef struct [[gnu::packed]] {
    uint32_t a;
    uint16_t b;
    uint16_t c;
    uint8_t d[8];
} guid_t;

typedef struct [[gnu::packed]] {
    uint8_t signature[8];
    uint32_t revision;
    uint32_t header_size;
    uint32_t header_checksum;
    uint32_t reserved;
    uint64_t header_lba;
    uint64_t backup_lba;
    uint64_t data_start_lba;
    uint64_t data_end_lba;
    guid_t guid;
    uint64_t partitions_lba;
    uint32_t num_partitions;
    uint32_t entry_size;
    uint32_t partitions_checksum;
} gpt_header_t;

typedef struct [[gnu::packed]] {
    guid_t type;
    guid_t guid;
    uint64_t head_lba;
    uint64_t tail_lba;
    uint64_t attributes;
    uint16_t name[36];
} gpt_partition_t;

uint32_t crc32(const void *data, size_t size) {
    uint32_t crc = 0xFFFFFFFF;

    while (size--) {
        uint8_t byte = *(const uint8_t *)data++;
        crc = crc ^ byte;

        for (int i = 0; i < 8; i++) {
            uint32_t mask = -(crc & 1);
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }

    return ~crc;
}

static int try_read_header(bdev_t *bdev, gpt_header_t *header, uint64_t block) {
    int error = pgcache_read(&bdev->data, header, sizeof(*header), block << bdev->block_shift);
    if (unlikely(error)) return -error;

    if (memcmp(header->signature, "EFI PART", 8)) return 0;

    uint32_t checksum = header->header_checksum;
    header->header_checksum = 0;
    uint32_t computed_checksum;

    if (header->header_size <= sizeof(*header)) {
        computed_checksum = crc32(header, header->header_size);
    } else {
        void *buffer = vmalloc(header->header_size);
        error = pgcache_read(&bdev->data, buffer, header->header_size, block << bdev->block_shift);
        if (unlikely(error)) {
            vmfree(buffer, header->header_size);
            return -error;
        }
        computed_checksum = crc32(buffer, header->header_size);
        vmfree(buffer, header->header_size);
    }

    if (checksum != computed_checksum) {
        printk("gpt: invalid checksum 0x%8x (got 0x%8x)\n", checksum, computed_checksum);
        return 0;
    }

    return 1;
}

static void format_guid(unsigned char buffer[36], const guid_t *guid) {
    snprintk(
            buffer,
            36,
            "%8x-%4x-%4x-%2x%2x-%2x%2x%2x%2x%2x%2x",
            guid->a,
            guid->b,
            guid->c,
            guid->d[0],
            guid->d[1],
            guid->d[2],
            guid->d[3],
            guid->d[4],
            guid->d[5],
            guid->d[6],
            guid->d[7]
    );
}

static int discover_gpt(bdev_t *bdev, const void *name, size_t length, part_cb_t cb, void *ctx) {
    static const guid_t EMPTY_GUID = {};

    gpt_header_t header;
    int error = try_read_header(bdev, &header, 1);
    if (unlikely(error < 0)) return error;

    if (!error) {
        error = try_read_header(bdev, &header, bdev->blocks - 1);
        if (unlikely(error < 0)) return error;
        if (!error) return 0;
    }

    size_t parts_size = header.entry_size * header.num_partitions;
    void *partitions = vmalloc(parts_size);

    error = -pgcache_read(&bdev->data, partitions, parts_size, header.partitions_lba << bdev->block_shift);
    if (unlikely(error)) goto exit;

    uint32_t real_checksum = crc32(partitions, parts_size);
    if (real_checksum != header.partitions_checksum) {
        printk("gpt: invalid partition array checksum 0x%8x (got 0x%8x)\n", real_checksum, header.partitions_checksum);
        goto exit;
    }

    // create id-based symlink
    unsigned char id_buf[36];
    format_guid(id_buf, &header.guid);

    unsigned char buffer[64];
    size_t link_length = snprintk(buffer, sizeof(buffer), "/dev/volumes/%S", id_buf, sizeof(id_buf));
    ASSERT(link_length <= sizeof(buffer));

    char *target;
    size_t targ_len = asprintk(&target, "../%S", name, length);
    error = -vfs_symlink(nullptr, buffer, link_length, target, targ_len);
    vmfree(target, targ_len);
    if (unlikely(error)) goto exit;

    for (size_t i = 0; i < header.num_partitions; i++) {
        gpt_partition_t *part = partitions + i * header.entry_size;
        if (!memcmp(&part->type, &EMPTY_GUID, sizeof(EMPTY_GUID))) continue;

        format_guid(id_buf, &part->guid);

        cb(part->head_lba, part->tail_lba - part->head_lba + 1, id_buf, sizeof(id_buf), ctx);
    }

    error = 1;
exit:
    vmfree(partitions, parts_size);
    return error;
}

static const discover_func_t discover_funcs[] = {
        discover_gpt,
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
