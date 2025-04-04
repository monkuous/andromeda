#include "fat.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/pgcache.h"
#include "fs/vfs.h"
#include "mem/pmap.h"
#include "mem/pmem.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/container.h"
#include "util/panic.h"
#include "util/time.h"
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <time.h>

#define FAT_NAME_LEN 11

static const inode_ops_t fat_inode_ops;

typedef struct {
    fs_t base;
    bdev_t *device;
    uint64_t fat_offset;
    uint64_t root_block;
    uint64_t root_size;
    int fat_entry_size; // 1 means 12 bits
    int cluster_block_shift;
    uint64_t data_block;
} fatfs_t;

typedef struct {
    inode_t base;
    uint32_t cluster;
    struct {
        uint32_t cluster;
        uint64_t idx;
        size_t offset;
    } cur;
} fat_inode_t;

typedef struct [[gnu::packed, gnu::aligned(4)]] {
    uint8_t name[FAT_NAME_LEN];
    uint8_t attr;
    uint8_t nt_reserved;
    uint8_t creation_time_cs;
    uint16_t creation_time_2s;
    uint16_t creation_date;
    uint16_t access_date;
    uint16_t cluster_high;
    uint16_t write_time;
    uint16_t write_date;
    uint16_t cluster_low;
    uint32_t size;
} fat_dirent_t;

#define DENT_READ_ONLY 1
#define DENT_HIDDEN 2
#define DENT_SYSTEM 4
#define DENT_VOLUME_ID 8
#define DENT_DIRECTORY 16
#define DENT_ARCHIVE 32

static uint32_t extend_cluster(fatfs_t *fs, uint32_t value) {
    switch (fs->fat_entry_size) {
    case 1: return value | (value >= 0xff7 ? 0xfffff000 : 0);
    case 2: return value | (value >= 0xfff7 ? 0xffff0000 : 0);
    case 4: return value | (value >= 0xffffff7 ? 0xf0000000 : 0);
    default: UNREACHABLE(); break;
    }
}

static int next_cluster(fatfs_t *fs, uint32_t *cluster) {
    uint32_t prev = *cluster;

    size_t size = fs->fat_entry_size;
    uint64_t offset = fs->fat_offset + prev * fs->fat_entry_size;

    if (fs->fat_entry_size == 1) {
        offset += prev >> 1;
        size += 1;
    }

    uint32_t value = 0;
    int error = pgcache_read(&fs->device->data, &value, size, offset);
    if (unlikely(error)) return error;

    if (fs->fat_entry_size == 1) {
        if (prev & 1) value >>= 4;
        else value &= 0xfff;
    }

    *cluster = extend_cluster(fs, value);
    return 0;
}

static int fat_pgcache_read_page(pgcache_t *self, page_t *page, uint64_t idx) {
    fat_inode_t *inode = container(fat_inode_t, base.data, self);
    fatfs_t *fs = (fatfs_t *)inode->base.filesystem;
    uint32_t clust_size = fs->base.block_size;

    if (idx < inode->cur.idx || (idx == inode->cur.idx && inode->cur.offset != 0)) {
        inode->cur.cluster = inode->cluster;
        inode->cur.idx = 0;
        inode->cur.offset = 0;
    }

    if (inode->cur.cluster >= 2) {
        while (inode->cur.idx < idx) {
            int error = next_cluster(fs, &inode->cur.cluster);
            if (unlikely(error)) return error;

            inode->cur.offset += clust_size;

            if (inode->cur.offset == PAGE_SIZE) {
                inode->cur.idx += 1;
                inode->cur.offset = 0;
            }
        }

        uint32_t phys = page_to_phys(page);

        while (inode->cur.offset < PAGE_SIZE) {
            if (inode->cur.cluster >= 0xffffff8) {
                memset(pmap_tmpmap(phys) + inode->cur.offset, 0, PAGE_SIZE - inode->cur.offset);
                return 0;
            }

            int error = fs->device->ops->read(
                    fs->device,
                    phys + inode->cur.offset,
                    fs->data_block + ((inode->cur.cluster - 2) << fs->cluster_block_shift),
                    1ul << fs->cluster_block_shift
            );
            if (unlikely(error)) return error;

            error = next_cluster(fs, &inode->cur.cluster);
            if (unlikely(error)) return error;

            inode->cur.offset += clust_size;
        }

        inode->cur.idx += 1;
        inode->cur.offset = 0;
    } else {
        uint64_t start = idx << PAGE_SHIFT;

        if (start < fs->root_size) {
            uint64_t avail = fs->root_size - start;

            if (avail < PAGE_SIZE) {
                memset(pmap_tmpmap(page_to_phys(page)) + avail, 0, PAGE_SIZE - avail);
            } else {
                avail = PAGE_SIZE;
            }

            return fs->device->ops->read(
                    fs->device,
                    page_to_phys(page),
                    fs->root_block + (start >> fs->device->block_shift),
                    avail >> fs->device->block_shift
            );
        } else {
            memset(pmap_tmpmap(page_to_phys(page)), 0, PAGE_SIZE);
        }
    }

    return 0;
}

static const pgcache_ops_t fat_pgcache_ops = {
        .read_page = fat_pgcache_read_page,
};

static void get_dir_info(fatfs_t *fs, fat_inode_t *inode, uint64_t *ino_offset, uint64_t *max) {
    if (inode->cluster >= 2) {
        if (ino_offset) {
            *ino_offset = (fs->data_block << fs->device->block_shift) + (uint64_t)inode->cluster * fs->base.block_size;
        }

        *max = inode->base.blocks * fs->base.block_size;
    } else {
        if (ino_offset) *ino_offset = fs->root_block << fs->device->block_shift;
        *max = fs->root_size;
    }
}

static size_t conv_fatname(unsigned char *out, fat_dirent_t *entry) {
    unsigned char *start = out;
    size_t last = 0;

    for (size_t i = 0; i < sizeof(entry->name); i++) {
        if (i == 8) {
            *out++ = '.';
            last = i;
        }

        unsigned char c = entry->name[i];
        if (c >= 'A' && c <= 'Z') c += 'a' - 'A';

        if (c != ' ') {
            if (last != i) {
                size_t cnt = i - last;
                memset(out, ' ', cnt);
                out += cnt;
            }

            *out++ = c;
            last = i + 1;
        }
    }

    return out - start;
}

static ssize_t emit_direntry(file_t *self, void *buffer, size_t size) {
    fat_inode_t *inode = (fat_inode_t *)self->inode;
    fatfs_t *fs = (fatfs_t *)inode->base.filesystem;

    // using alloca is fine here, the size is small and known at compile time
    // the name is at most 13 bytes: 8.3 is 12 bytes, and a null terminator makes it 13
    readdir_output_t *value = __builtin_alloca(offsetof(readdir_output_t, name) + 13);
    uint64_t orig_pos = self->position;

    if (self->position == 0) {
        self->position++;
        value->inode = inode->base.ino;
        value->offset = 0;
        value->length = offsetof(readdir_output_t, name) + 2;
        value->type = DT_DIR;
        value->name[0] = '.';
        value->name[1] = 0;
    } else if (self->position == 1) {
        self->position++;
        value->inode = vfs_parent(self->path)->inode->ino;
        value->offset = 0;
        value->length = offsetof(readdir_output_t, name) + 3;
        value->type = DT_DIR;
        value->name[0] = '.';
        value->name[1] = '.';
        value->name[2] = 0;
    } else {
        uint64_t ino_offset;
        uint64_t max;
        get_dir_info(fs, inode, &ino_offset, &max);
        max += 2;

        value->length = 0;

        for (; self->position < max && !value->length; self->position += sizeof(fat_dirent_t)) {
            uint64_t off = self->position - 2;
            fat_dirent_t entry;
            int error = pgcache_read(&inode->base.data, &entry, sizeof(entry), off);
            if (unlikely(error)) return error;

            if (entry.name[0] == 0) break;
            if (entry.name[0] == 0xe5) continue;

            if (entry.attr & DENT_VOLUME_ID) continue;

            if (!memcmp(entry.name, ".          ", 11)) continue;
            if (!memcmp(entry.name, "..         ", 11)) continue;

            size_t len = conv_fatname(value->name, &entry);
            if (!len) continue;

            value->inode = ino_offset + off;
            value->offset = self->position;
            value->length = offsetof(readdir_output_t, name) + len + 1;
            value->type = entry.attr & DENT_DIRECTORY ? DT_DIR : DT_REG;
            value->name[len] = 0;

            dentry_t *dent = get_existing_dentry(self->path, value->name, len);
            if (dent) {
                dent = vfs_mount_top(dent);

                if (dent->inode) {
                    value->inode = dent->inode->ino;
                    value->type = IFTODT(dent->inode->mode);
                }
            }
        }

        if (!value->length) return 0;
    }

    if (value->length > size) {
        self->position = orig_pos;
        return 0;
    }

    int error = -user_memcpy(buffer, value, value->length);
    if (unlikely(error)) {
        self->position = orig_pos;
        return error;
    }

    return value->length;
}

static int fat_dir_readdir(file_t *self, void *buffer, size_t *size) {
    size_t rem = *size;
    size_t tot = 0;

    while (rem) {
        ssize_t cur = emit_direntry(self, buffer, rem);
        if (unlikely(cur < 0)) return cur;
        if (cur == 0) break;

        buffer += cur;
        tot += cur;
        rem -= cur;
    }

    *size = tot;
    return 0;
}

static const file_ops_t fat_dir_ops = {
        .readdir = fat_dir_readdir,
};

static void fat_inode_free(inode_t *ptr) {
    fat_inode_t *self = (fat_inode_t *)ptr;
    vmfree(self, sizeof(*self));
}

static bool make_fat_name(uint8_t buffer[FAT_NAME_LEN], dname_t *name) {
    size_t offset = 0;
    bool last_was_space = false;
    bool in_ext = false;

    for (size_t i = 0; i < name->length; i++) {
        unsigned char c = name->data[i];
        if (c >= 'A' && c <= 'Z') return false;
        if (c >= 'a' && c <= 'z') c -= 'a' - 'A';

        if (c == '.') {
            if (in_ext || last_was_space) return false;

            in_ext = true;

            if (offset < 8) {
                memset(&buffer[offset], 0x20, 8 - offset);
                offset = 8;
            }

            continue;
        }

        if (offset >= (in_ext ? FAT_NAME_LEN : 8)) return false;

        buffer[offset++] = c;
        last_was_space = c == ' ';
    }

    if (last_was_space) return false;

    if (offset < FAT_NAME_LEN) {
        memset(&buffer[offset], 0x20, FAT_NAME_LEN - offset);
    }

    return true;
}

static struct timespec create_timespec(uint16_t date, uint16_t time, uint16_t time_cs) {
    struct timespec spec;

    spec.tv_sec = get_time_from_date(1980 + (date >> 9), (date >> 5) & 15, date & 31);
    spec.tv_sec += (time >> 11) * 3600;     // time[15..11] is in hours
    spec.tv_sec += ((time >> 5) & 63) * 60; // time[10..5] is in minutes
    spec.tv_sec += (time & 31) * 2;         // time[4..0] is in units of 2 seconds
    spec.tv_sec += time_cs / 100;
    spec.tv_nsec = (time_cs % 100) * 10000000; // time_cs is in centiseconds, 1 cs = 10,000,000 ns

    return spec;
}

static int get_block_count(fatfs_t *fs, uint32_t cluster, blkcnt_t *out) {
    if (cluster < 2) return 0;

    blkcnt_t len = 0;

    while (cluster < 0xffffff8) {
        len += 1;
        int error = next_cluster(fs, &cluster);
        if (unlikely(error)) return error;
    }

    *out = len;
    return 0;
}

static int dirino_init(fatfs_t *fs, fat_inode_t *inode) {
    uint64_t max;
    get_dir_info(fs, inode, nullptr, &max);

    for (uint64_t i = 0; i < max; i += sizeof(fat_dirent_t)) {
        fat_dirent_t entry;
        int error = pgcache_read(&inode->base.data, &entry, sizeof(entry), i);
        if (unlikely(error)) return error;

        if (entry.name[0] == 0) break;
        if (entry.name[0] == 0xe5) continue;

        if (!memcmp(entry.name, ".          ", 11)) continue;
        if (!memcmp(entry.name, "..         ", 11)) continue;

        if (entry.attr & DENT_DIRECTORY) inode->base.nlink += 1;
    }

    return 0;
}

static int create_inode(inode_t **out, fatfs_t *fs, fat_dirent_t *entry, ino_t ino) {
    fat_inode_t *inode = vmalloc(sizeof(*inode));
    memset(inode, 0, sizeof(*inode));
    inode->base.ops = &fat_inode_ops;
    inode->base.filesystem = &fs->base;
    inode->base.ino = ino;
    inode->base.data.ops = &fat_pgcache_ops;

    inode->cluster = extend_cluster(fs, entry->cluster_low | ((uint32_t)entry->cluster_high << 16));
    inode->cur.cluster = inode->cluster;

    if (entry->attr & DENT_DIRECTORY) {
        inode->base.mode = S_IFDIR | 0777;
        inode->base.nlink = 2;
        inode->base.directory = &fat_dir_ops;

        int error = get_block_count(fs, inode->cluster, &inode->base.blocks);
        if (unlikely(error)) {
            vmfree(inode, sizeof(*inode));
            return error;
        }

        pgcache_resize(
                &inode->base.data,
                inode->cluster >= 2 ? (uint64_t)inode->base.blocks * fs->base.block_size : fs->root_size
        );

        error = dirino_init(fs, inode);
        if (unlikely(error)) {
            pgcache_resize(&inode->base.data, 0);
            vmfree(inode, sizeof(*inode));
            return error;
        }
    } else {
        inode->base.mode = S_IFREG | 0777;
        if (entry->attr & DENT_READ_ONLY) inode->base.mode &= ~0222;

        inode->base.nlink = 1;
        inode->base.size = entry->size;
        inode->base.blocks = (entry->size + (fs->base.block_size - 1)) / fs->base.block_size;

        pgcache_resize(&inode->base.data, inode->base.size);
    }

    inode->base.atime = create_timespec(entry->access_date, 0, 0);
    inode->base.mtime = create_timespec(entry->write_date, entry->write_time, 0);
    inode->base.ctime = inode->base.mtime;

    init_inode(&fs->base, &inode->base);
    *out = &inode->base;
    return 0;
}

static int fat_inode_lookup(inode_t *ptr, dentry_t *entry) {
    uint8_t fat_name[FAT_NAME_LEN];
    if (!make_fat_name(fat_name, &entry->name)) return ENOENT;

    fatfs_t *fs = (fatfs_t *)ptr->filesystem;
    fat_inode_t *self = (fat_inode_t *)ptr;

    uint64_t ino_offset;
    uint64_t max;

    get_dir_info(fs, self, &ino_offset, &max);

    for (uint64_t off = 0; off < max; off += sizeof(fat_dirent_t)) {
        fat_dirent_t cur;
        int error = pgcache_read(&self->base.data, &cur, sizeof(cur), off);
        if (unlikely(error)) return error;

        if (cur.name[0] == 0) break;
        if (cur.name[0] == 0xe5) continue;
        if (cur.attr & DENT_VOLUME_ID) continue;
        if (memcmp(cur.name, fat_name, sizeof(fat_name))) continue;

        return create_inode(&entry->inode, fs, &cur, ino_offset + off);
    }

    return ENOENT;
}

static const inode_ops_t fat_inode_ops = {
        .free = fat_inode_free,
        .directory.lookup = fat_inode_lookup,
};

static void fatfs_free(fs_t *ptr) {
    fatfs_t *self = (fatfs_t *)ptr;
    ASSERT(self->device->fs == &self->base);
    self->device->fs = nullptr;
    vmfree(self, sizeof(*self));
}

static const fs_ops_t fatfs_ops = {.free = fatfs_free};

typedef struct [[gnu::packed]] {
    uint8_t drive;
    uint8_t reserved;
    uint8_t boot_sig;
    uint32_t serial;
    uint8_t label[11];
    uint8_t fstype[8];
} ebpb_common_t;

typedef struct [[gnu::packed, gnu::aligned(4)]] {
    uint8_t jmp_boot[3];
    uint8_t oem_id[8];
    uint16_t sector_size;
    uint8_t cluster_size;
    uint16_t num_reserved;
    uint8_t num_fats;
    uint16_t root_size;
    uint16_t num_sectors_16;
    uint8_t media;
    uint16_t fat_size_16;
    uint16_t track_size;
    uint16_t num_heads;
    uint32_t volume_offset;
    uint32_t num_sectors_32;
    union {
        ebpb_common_t fat16;
        struct [[gnu::packed]] {
            uint32_t fat_size;
            uint16_t flags;
            uint16_t fs_version;
            uint32_t root_cluster;
            uint16_t fs_info_sector;
            uint16_t backup_boot_sector;
            uint8_t reserved[12];
            ebpb_common_t tail;
        } fat32;
    };
    uint8_t reserved[420];
    uint16_t signature;
} bpb_t;

static_assert(offsetof(bpb_t, signature) == 510, "wrong bpb_t.signature offset");
static_assert(sizeof(bpb_t) == 512, "wrong bpb_t size");

int fat_create(fs_t **out, void *ctx) {
    bdev_t *dev = ctx;

    size_t block_size = 1ul << dev->block_shift;
    size_t block_mask = block_size - 1;

    bpb_t bpb;
    int error = pgcache_read(&dev->data, &bpb, sizeof(bpb), 0);
    if (unlikely(error)) return error;

    if (bpb.signature != 0xaa55 || !bpb.sector_size || !bpb.cluster_size || !bpb.num_reserved || !bpb.num_fats ||
        bpb.sector_size < block_size) {
        return EINVAL;
    }

    uint32_t cluster_size = (uint32_t)bpb.sector_size * bpb.cluster_size;
    if ((cluster_size & (cluster_size - 1)) || cluster_size > PAGE_SIZE) return EINVAL;

    uint32_t sectors = bpb.num_sectors_16 ? bpb.num_sectors_16 : bpb.num_sectors_32;
    if (!sectors) return EINVAL;

    uint64_t blocks = ((uint64_t)sectors * bpb.sector_size - 1 + block_mask) >> dev->block_shift;
    if (blocks > dev->blocks) return EINVAL;

    bool is_fat32 = !bpb.fat_size_16;
    uint32_t fat_size = is_fat32 ? bpb.fat32.fat_size : bpb.fat_size_16;
    if (!fat_size) return EINVAL;

    uint64_t fat_offset = bpb.num_reserved;
    uint64_t root_offset = fat_offset + (uint64_t)bpb.num_fats * fat_size;
    uint64_t root_size = ((uint32_t)bpb.root_size * 32 + (bpb.sector_size - 1)) / bpb.sector_size;
    uint64_t data_offset = root_offset + root_size;

    if ((is_fat32 && root_size) || data_offset >= sectors) return EINVAL;

    uint32_t data_sectors = sectors - data_offset;
    uint32_t data_clusters = data_sectors / bpb.cluster_size;

    if (is_fat32) {
        if (root_size) return EINVAL;

        if (bpb.fat32.flags & 0x80) {
            uint64_t idx = bpb.fat32.flags & 15;
            if (idx >= bpb.num_fats) return EINVAL;

            fat_offset += (uint64_t)idx * fat_size;
        }
    }

    fatfs_t *fs = vmalloc(sizeof(*fs));
    memset(fs, 0, sizeof(*fs));

    fs->base.ops = &fatfs_ops;
    fs->base.device = dev->id;
    fs->base.flags = ST_RDONLY;
    fs->base.block_size = cluster_size;
    fs->base.max_name_len = 8; // TODO: VFAT
    fs->base.blocks = data_clusters;
    fs->device = dev;
    fs->fat_offset = fat_offset * bpb.sector_size;
    fs->cluster_block_shift = __builtin_ctz(cluster_size) - dev->block_shift;
    fs->data_block = (data_offset * bpb.sector_size) >> dev->block_shift;

    fat_dirent_t root_dirent = {
            .attr = DENT_DIRECTORY,
            .access_date = (1 << 5) | 1,
            .creation_date = (1 << 5) | 1,
            .write_date = (1 << 5) | 1,
    };

    if (!is_fat32) {
        fs->root_block = (root_offset * bpb.sector_size) >> dev->block_shift;
        fs->root_size = root_size * bpb.sector_size;
        fs->fat_entry_size = 1 + (data_clusters >= 4085);
    } else {
        fs->fat_entry_size = 4;
        root_dirent.cluster_low = bpb.fat32.root_cluster;
        root_dirent.cluster_high = bpb.fat32.root_cluster >> 16;
    }

    inode_t *root;
    error = create_inode(&root, fs, &root_dirent, 1);
    if (unlikely(error)) {
        vmfree(fs, sizeof(*fs));
        return error;
    }

    init_fs(&fs->base, root);
    inode_deref(root);

    dev->fs = &fs->base;
    *out = &fs->base;
    return error;
}
