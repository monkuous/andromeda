#include "iso9660.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/pgcache.h"
#include "fs/vfs.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/container.h"
#include "util/panic.h"
#include "util/time.h"
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <time.h>

static const file_ops_t iso9660_dir_ops;
static const inode_ops_t iso9660_inode_ops;

typedef struct {
    fs_t base;
    bdev_t *device;
    int block_shift;
} iso9660_fs_t;

typedef struct {
    uint32_t block;
    uint32_t count;
} extent_t;

typedef struct {
    inode_t base;
    extent_t *extents;
    size_t num_extents;
    struct {
        extent_t *extent;
        uint64_t block0;
    } cur;
} iso9660_inode_t;

static int iso9660_pgcache_read_page(pgcache_t *self, page_t *page, uint64_t idx) {
    iso9660_inode_t *inode = container(iso9660_inode_t, base.data, self);
    iso9660_fs_t *fs = (iso9660_fs_t *)inode->base.filesystem;

    int bpconvs = PAGE_SHIFT - fs->block_shift;
    int bdconvs = fs->block_shift - fs->device->block_shift;

    uint64_t fblock = idx << bpconvs;

    if (fblock < inode->cur.block0) {
        inode->cur.extent = inode->extents;
        inode->cur.block0 = 0;
    }

    for (;;) {
        uint64_t max_block = (uint64_t)inode->cur.block0 + inode->cur.extent->count;
        if (fblock < max_block) break;
        inode->cur.extent++;
        inode->cur.block0 = max_block;
    }

    uint32_t phys = page_to_phys(page);
    uint32_t eblock = fblock - inode->cur.block0;
    uint32_t eblrem = inode->cur.extent->count - eblock;

    for (;;) {
        uint64_t blocks = (PAGE_SIZE - (phys & PAGE_MASK)) >> fs->block_shift;
        if (blocks > eblrem) blocks = eblrem;

        uint64_t lba = inode->cur.extent->block + eblock;
        int error = fs->device->ops->rphys(fs->device, phys, lba << bdconvs, blocks << bdconvs);
        if (unlikely(error)) return error;

        phys += blocks << fs->block_shift;
        if (!(phys & PAGE_MASK)) break;

        if (inode->cur.extent == &inode->extents[inode->num_extents - 1]) {
            memset(pmap_tmpmap(phys & ~PAGE_MASK) + (phys & PAGE_MASK), 0, PAGE_SIZE - (phys & PAGE_MASK));
            break;
        }

        inode->cur.block0 += inode->cur.extent->count;
        inode->cur.extent++;
        eblock = 0;
        eblrem = inode->cur.extent->count;
    }

    return 0;
}

static const pgcache_ops_t iso9660_pgcache_ops = {
        .read_page = iso9660_pgcache_read_page,
};

typedef struct {
    uint16_t le;
    uint16_t be;
} uint16_lb_t;

typedef struct {
    uint32_t le;
    uint32_t be;
} uint32_lb_t;

typedef struct [[gnu::packed]] {
    uint8_t year[4];
    uint8_t month[2];
    uint8_t day[2];
    uint8_t hour[2];
    uint8_t minute[2];
    uint8_t second[2];
    uint8_t centisecond[2];
    int8_t timezone; /* in units of 15 minutes */
} dec_datetime_t;

typedef struct [[gnu::packed]] {
    uint8_t year; // offset from 1990
    uint8_t month;
    uint8_t day;
    uint8_t hour;
    uint8_t minute;
    uint8_t second;
    int8_t timezone; /* in units of 15 minutes */
} datetime_t;

typedef struct [[gnu::packed]] {
    uint8_t length;
    uint8_t ext_length;
    uint32_lb_t extent_lba;
    uint32_lb_t extent_len;
    datetime_t record_time;
    uint8_t flags;
    uint8_t file_unit_size;
    uint8_t interleave_gap;
    uint16_lb_t volume_id;
    uint8_t name_length;
    uint8_t name[1];
} dirent_t;

typedef union {
    dirent_t common;
    uint8_t padding[255];
} full_dirent_t;

#define DENT_HIDDEN 0x01
#define DENT_DIRECTORY 0x02
#define DENT_ASSOCIATED 0x04
#define DENT_RECORD 0x08
#define DENT_UID_GID 0x10
#define DENT_MID_EXTENT 0x80

static struct timespec create_timespec(datetime_t *time) {
    struct timespec spec;
    spec.tv_sec = get_time_from_date(time->year + 1900, time->month, time->day);
    spec.tv_sec += time->hour * 3600;
    spec.tv_sec += time->minute * 60;
    spec.tv_sec += time->second;
    spec.tv_nsec = 0;
    spec.tv_sec -= time->timezone * 15 * 60;
    return spec;
}

static int dirino_init(iso9660_fs_t *, iso9660_inode_t *inode) {
    uint64_t offset = 0;

    while (offset < inode->base.size) {
        dirent_t entry;
        int error = pgcache_read(&inode->base.data, &entry, sizeof(entry), offset);
        if (unlikely(error)) return error;
        if (!entry.length) break;

        // filter out . and ..
        if (entry.name_length != 1 || entry.name[0] >= 2) {
            if (entry.flags & DENT_DIRECTORY) inode->base.nlink += 1;
        }

        offset += entry.length;
    }

    return 0;
}

static int create_inode(inode_t **out, iso9660_fs_t *fs, dirent_t *entry, ino_t ino, extent_t *extents, size_t extc) {
    iso9660_inode_t *inode = vmalloc(sizeof(*inode));
    memset(inode, 0, sizeof(*inode));
    inode->base.ops = &iso9660_inode_ops;
    inode->base.filesystem = &fs->base;
    inode->base.ino = ino;
    inode->base.data.ops = &iso9660_pgcache_ops;
    inode->base.size = entry->extent_len.le;
    inode->base.blocks = (inode->base.size + (fs->base.block_size - 1)) >> fs->block_shift;
    inode->base.atime = create_timespec(&entry->record_time);
    inode->base.ctime = inode->base.atime;
    inode->base.mtime = inode->base.atime;

    inode->extents = extents;
    inode->num_extents = extc;
    inode->cur.extent = inode->extents;

    pgcache_resize(&inode->base.data, inode->base.size);

    if (entry->flags & DENT_DIRECTORY) {
        inode->base.mode = S_IFDIR | 0777;
        inode->base.nlink = 2;
        inode->base.directory = &iso9660_dir_ops;

        int error = dirino_init(fs, inode);
        if (unlikely(error)) {
            pgcache_resize(&inode->base.data, 0);
            vmfree(inode, sizeof(*inode));
            return 0;
        }
    } else {
        inode->base.mode = S_IFREG | 0777;
        inode->base.nlink = 1;
    }

    init_inode(&fs->base, &inode->base);
    *out = &inode->base;
    return 0;
}

static void iso9660_inode_free(inode_t *ptr) {
    iso9660_inode_t *self = (iso9660_inode_t *)ptr;
    vmfree(self, sizeof(*self));
}

static uint64_t fblock_to_lba(iso9660_inode_t *inode, uint64_t fblock) {
    extent_t *cur = inode->extents;

    while (fblock >= cur->count) {
        fblock -= cur->count;
        cur++;
    }

    return fblock + cur->block;
}

static void make_extent(iso9660_fs_t *fs, extent_t *ext, dirent_t *entry) {
    if (entry->file_unit_size) panic("iso9660: interleaved files are not supported");

    ext->block = entry->extent_lba.le;
    ext->count = (entry->extent_len.le + (fs->base.block_size - 1)) >> fs->block_shift;
}

static int get_extent_list(
        iso9660_fs_t *fs,
        iso9660_inode_t *dir,
        dirent_t entry, // passed by value to prevent read values from leaking back into the main dirent
        uint64_t offset,
        extent_t **aout,
        size_t *lout
) {
    extent_t *extents = nullptr;
    size_t count = 0;

    for (;;) {
        size_t old_size = count * sizeof(*extents);
        size_t new_size = old_size + sizeof(*extents);
        extent_t *new_list = vmalloc(new_size);
        memcpy(new_list, extents, old_size);
        vmfree(extents, old_size);
        extents = new_list;

        make_extent(fs, &extents[count], &entry);
        count++;

        if (!(entry.flags & DENT_MID_EXTENT)) break;

        offset += entry.length;
        int error = pgcache_read(&dir->base.data, &entry, sizeof(entry), offset);
        if (unlikely(error)) {
            vmfree(extents, new_size);
            return error;
        }
    }

    *aout = extents;
    *lout = count;

    return 0;
}

static int iso9660_inode_lookup(inode_t *ptr, dentry_t *entry) {
    iso9660_inode_t *self = (iso9660_inode_t *)ptr;
    iso9660_fs_t *fs = (iso9660_fs_t *)self->base.filesystem;

    uint64_t offset = 0;
    int error = 0;

    while (offset < self->base.size) {
        full_dirent_t cur;
        error = pgcache_read(&self->base.data, &cur, sizeof(cur), offset);
        if (unlikely(error)) return error;
        if (!cur.common.length) break;

        // filter out . and ..
        if (cur.common.name_length != 1 || cur.common.name[0] >= 2) {
            // transform name so that it can be memcmp'd
            size_t len = cur.common.name_length;

            if (!(cur.common.flags & DENT_DIRECTORY)) {
                // get rid of ;<version>
                while (len > 0 && cur.common.name[len - 1] != ';') len--;
                if (len) len--;

                // if there is no extension, get rid of the dot
                if (len > 1 && cur.common.name[len - 1] == '.') len--;
            }

            for (size_t i = 0; i < len; i++) {
                unsigned char c = cur.common.name[i];
                if (c >= 'A' && c <= 'Z') cur.common.name[i] = c + ('a' - 'A');
            }

            if (len == entry->name.length && !memcmp(cur.common.name, entry->name.data, len)) {
                extent_t *extents;
                size_t ext_count;
                error = get_extent_list(fs, self, cur.common, offset, &extents, &ext_count);
                if (unlikely(error)) return error;

                return create_inode(
                        &entry->inode,
                        fs,
                        &cur.common,
                        (fblock_to_lba(self, offset >> fs->block_shift) << fs->block_shift) + offset,
                        extents,
                        ext_count
                );
            }
        }

        offset += cur.common.length;
    }

    return ENOENT;
}

static const inode_ops_t iso9660_inode_ops = {
        .free = iso9660_inode_free,
        .directory.lookup = iso9660_inode_lookup,
};

static void iso9660_fs_free(fs_t *ptr) {
    iso9660_fs_t *self = (iso9660_fs_t *)ptr;
    ASSERT(self->device->fs == &self->base);
    self->device->fs = nullptr;
    vmfree(self, sizeof(*self));
}

static const fs_ops_t iso9660_fs_ops = {
        .free = iso9660_fs_free,
};

typedef struct [[gnu::packed, gnu::aligned(4)]] {
    uint8_t type;
    uint8_t id[5];
    uint8_t version;
    union {
        struct [[gnu::packed]] {
            uint8_t reserved0;
            uint8_t system_id[32];
            uint8_t volume_id[32];
            uint8_t reserved1[8];
            uint32_lb_t num_blocks;
            uint8_t reserved3[32];
            uint16_lb_t num_disks;
            uint16_lb_t disk_id;
            uint16_lb_t block_size;
            uint32_lb_t path_table_size;
            uint32_t le_path_table_block;
            uint32_t le_path_table_opt_block;
            uint32_t be_path_table_block;
            uint32_t be_path_table_opt_block;
            dirent_t root_dirent;
            uint8_t volume_set_id[128];
            uint8_t publisher_id[128];
            uint8_t preparer_id[128];
            uint8_t application_id[128];
            uint8_t copyright_id[37];
            uint8_t abstract_id[37];
            uint8_t bibliograpy_id[37];
            dec_datetime_t creation_time;
            dec_datetime_t modification_time;
            dec_datetime_t expiration_time;
            dec_datetime_t effective_time;
            int8_t structure_version;
        } primary;
        uint8_t padding[2041];
    };
} voldesc_t;

static_assert(sizeof(voldesc_t) == 2048, "wrong size for voldesc_t");

#define VD_BOOT_RECORD 0
#define VD_PRIMARY 1
#define VD_SUPPLEMENTARY 2
#define VD_PARTITION 3
#define VD_TERMINATOR 0xff

int iso9660_create(fs_t **out, void *ctx) {
    bdev_t *dev = ctx;

    size_t block_size = 1ul << dev->block_shift;
    size_t block_mask = block_size - 1;
    if (block_size > 0x8000) return EINVAL;

    uint64_t cur_dblk = 0x8000 >> dev->block_shift;
    size_t descs_size = (sizeof(voldesc_t) + block_mask) & ~block_mask;
    size_t descs_nblk = descs_size >> dev->block_shift;
    void *descs = vmalloc(descs_size);
    voldesc_t *primdesc = nullptr;

    int error = 0;

    do {
        if (cur_dblk + (descs_nblk - 1) >= dev->blocks) {
            error = EINVAL;
            goto exit;
        }

        error = dev->ops->rvirt(dev, descs, cur_dblk, descs_nblk);
        if (unlikely(error)) goto exit;

        for (size_t offset = 0; offset < descs_size; offset += sizeof(voldesc_t)) {
            voldesc_t *desc = descs + offset;

            if (memcmp(desc->id, "CD001", 5)) {
                error = EINVAL;
                goto exit;
            }

            if (desc->type == VD_TERMINATOR) {
                // Descriptor list does not contain VD_PRIMARY
                error = EINVAL;
                goto exit;
            }

            if (desc->type == VD_PRIMARY) {
                primdesc = desc;
                break;
            }
        }
    } while (!primdesc);

    if (primdesc->version != 1 || primdesc->primary.structure_version != 1 ||
        (primdesc->primary.block_size.le & (primdesc->primary.block_size.le - 1)) ||
        primdesc->primary.block_size.le < block_size || primdesc->primary.block_size.le > PAGE_SIZE ||
        primdesc->primary.num_disks.le != 1 || (primdesc->primary.root_dirent.flags & DENT_MID_EXTENT)) {
        error = EINVAL;
        goto exit;
    }

    iso9660_fs_t *fs = vmalloc(sizeof(*fs));
    memset(fs, 0, sizeof(*fs));

    fs->base.ops = &iso9660_fs_ops;
    fs->base.device = dev->id;
    fs->base.flags = ST_RDONLY;
    fs->base.block_size = primdesc->primary.block_size.le;
    fs->base.max_name_len = 255;
    fs->base.blocks = primdesc->primary.num_blocks.le;
    fs->device = dev;
    fs->block_shift = __builtin_ctz(fs->base.block_size);

    extent_t *extents = vmalloc(sizeof(*extents));
    make_extent(fs, extents, &primdesc->primary.root_dirent);

    inode_t *root;
    error = create_inode(&root, fs, &primdesc->primary.root_dirent, 0, extents, 1);
    if (unlikely(error)) {
        vmfree(fs, sizeof(*fs));
        goto exit;
    }

    init_fs(&fs->base, root);
    inode_deref(root);

    dev->fs = &fs->base;
    *out = &fs->base;
exit:
    vmfree(descs, descs_size);
    return error;
}
