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
#include <bits/posix/stat.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <time.h>

#define INO_BASE 0

static const file_ops_t iso9660_dir_ops;
static const inode_ops_t iso9660_inode_ops;

typedef struct {
    fs_t base;
    bdev_t *device;
    int block_shift;
    uint8_t rr_skip;
    bool need_px;
} iso9660_fs_t;

typedef struct {
    uint32_t block;
    uint32_t count;
} extent_t;

typedef struct isoino {
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

static unsigned parse_field(uint8_t *data, size_t len) {
    unsigned value = 0;

    while (len--) {
        value = (value * 10) + (*data++ - '0');
    }

    return value;
}

static struct timespec create_timespec_long(dec_datetime_t *time) {
    unsigned year = parse_field(time->year, sizeof(time->year));
    unsigned month = parse_field(time->month, sizeof(time->month));
    unsigned day = parse_field(time->day, sizeof(time->day));
    unsigned hour = parse_field(time->hour, sizeof(time->hour));
    unsigned minute = parse_field(time->minute, sizeof(time->minute));
    unsigned second = parse_field(time->second, sizeof(time->second));
    unsigned centisecond = parse_field(time->centisecond, sizeof(time->centisecond));

    struct timespec spec;
    spec.tv_sec = get_time_from_date(year, month, day);
    spec.tv_sec += hour * 3600;
    spec.tv_sec += minute * 60;
    spec.tv_sec += second;
    spec.tv_nsec = centisecond * 10000000; // 1 cs = 10,000,000 ns
    spec.tv_sec -= time->timezone * 15 * 60;
    return spec;
}

struct rr_info {
    bool have_cl : 1;
    bool have_px : 1;
    bool have_rn : 1;
    bool have_tf_creation : 1;
    bool have_tf_modify : 1;
    bool have_tf_access : 1;
    bool have_tf_attributes : 1;
    bool have_tf_backup : 1;
    bool have_tf_expiration : 1;
    bool have_tf_effective : 1;
    struct {
        uint32_t lba;
    } cl;
    struct {
        uint32_t mode;
        uint32_t nlink;
        uint32_t uid;
        uint32_t gid;
        uint32_t ino;
    } px;
    struct {
        uint64_t dev;
    } pn;
    struct {
        void *target;
        size_t length;
    } sl;
    struct {
        void *data;
        size_t length;
    } nm;
    struct {
        struct timespec creation;
        struct timespec modify;
        struct timespec access;
        struct timespec attributes;
        struct timespec backup;
        struct timespec expiration;
        struct timespec effective;
    } tf;
};

typedef struct [[gnu::packed]] {
    uint16_t sig;
    uint8_t length;
    uint8_t version;
    union {
        struct [[gnu::packed]] {
            uint32_lb_t location;
            uint32_lb_t offset;
            uint32_lb_t length;
        } ce;
        struct [[gnu::packed]] {
            uint32_lb_t location;
        } cl;
        struct [[gnu::packed]] {
            uint8_t flags;
            uint8_t data[];
        } nm;
        struct [[gnu::packed]] {
            uint32_lb_t mode;
            uint32_lb_t nlink;
            uint32_lb_t uid;
            uint32_lb_t gid;
            uint32_lb_t ino;
        } px;
        struct [[gnu::packed]] {
            uint32_lb_t high;
            uint32_lb_t low;
        } pn;
        struct [[gnu::packed]] {
            uint8_t flags;
            uint8_t components[];
        } sl;
        struct [[gnu::packed]] {
            uint16_t check;
            uint8_t skip;
        } sp;
        struct [[gnu::packed]] {
            uint8_t flags;
            union {
                datetime_t sform[0];
                dec_datetime_t lform[0];
            };
        } tf;
    };
} susp_field_t;

#define SUSP_CE 0x4543 /* "CE" */
#define SUSP_CL 0x4c43 /* "CL" */
#define SUSP_NM 0x4d4e /* "NM" */
#define SUSP_PN 0x4e50 /* "PN" */
#define SUSP_PX 0x5850 /* "PX" */
#define SUSP_RE 0x4552 /* "RE" */
#define SUSP_SL 0x4c53 /* "SL" */
#define SUSP_SP 0x5053 /* "SP" */
#define SUSP_ST 0x5453 /* "ST" */
#define SUSP_TF 0x4654 /* "TF" */

typedef struct [[gnu::packed]] {
    uint8_t flags;
    uint8_t length;
    uint8_t data[];
} susp_sl_component_t;

#define SUSP_NM_CONTINUE 1
#define SUSP_NM_CURRENT 2
#define SUSP_NM_HOSTNAME 32

#define SUSP_SL_CONTINUE 1
#define SUSP_SL_CURRENT 2
#define SUSP_SL_PARENT 4
#define SUSP_SL_ROOT 8
#define SUSP_SL_MOUNT 16
#define SUSP_SL_HOSTNAME 32

#define SUSP_TF_CREATION 1
#define SUSP_TF_MODIFY 2
#define SUSP_TF_ACCESS 4
#define SUSP_TF_ATTRIBUTES 8
#define SUSP_TF_BACKUP 16
#define SUSP_TF_EXPIRATION 32
#define SUSP_TF_EFFECTIVE 64
#define SUSP_TF_LONG_FORM 128

static size_t get_susp_off(uint8_t name_len, uint8_t skip) {
    return ((offsetof(full_dirent_t, common.name) + name_len + 1) & ~1) + skip;
}

static int get_rr_info(iso9660_fs_t *fs, full_dirent_t *entry, struct rr_info *out) {
    if (fs->rr_skip == 0xff) return 0;

    size_t su_offs = get_susp_off(entry->common.name_length, fs->rr_skip);
    if (su_offs >= entry->common.length) return 0;

    susp_field_t *cur_su = (void *)entry + su_offs;
    size_t su_size = entry->common.length - su_offs;

    void *alloc_area = nullptr;
    size_t alloc_size = 0;

    bool sl_was_continue = false;

    for (;;) {
        susp_field_t *ce_field = nullptr;

        while (su_size >= 4) {
            if (su_size < cur_su->length) break;

            switch (cur_su->sig) {
            case SUSP_CE: ce_field = cur_su; break;
            case SUSP_CL:
                out->have_cl = true;
                out->cl.lba = cur_su->cl.location.le;
                break;
            case SUSP_PN: out->pn.dev = ((uint64_t)cur_su->pn.high.le << 32) | cur_su->pn.low.le; break;
            case SUSP_PX:
                out->have_px = true;
                out->px.mode = cur_su->px.mode.le;
                out->px.nlink = cur_su->px.nlink.le;
                out->px.uid = cur_su->px.uid.le;
                out->px.gid = cur_su->px.gid.le;
                out->px.ino = cur_su->px.ino.le;
                break;
            case SUSP_RE: out->have_rn = true; break;
            case SUSP_NM: {
                void *cdata = cur_su->nm.data;
                size_t clen = cur_su->length - offsetof(susp_field_t, nm.data);

                if (cur_su->nm.flags & SUSP_NM_CURRENT) {
                    cdata = ".";
                    clen = 1;
                } else if (cur_su->nm.flags & SUSP_NM_HOSTNAME) {
                    // TODO: Actually get the hostname properly
                    cdata = "<hostname>";
                    clen = 10;
                }

                size_t tlen = clen + out->nm.length;
                void *buffer = vmalloc(tlen);
                memcpy(buffer, out->nm.data, out->nm.length);
                memcpy(buffer + out->nm.length, cdata, clen);
                vmfree(out->nm.data, out->nm.length);
                out->nm.data = buffer;
                out->nm.length = tlen;
                break;
            }
            case SUSP_SL: {
                size_t offset = 0;
                size_t area_len = cur_su->length - offsetof(susp_field_t, sl.components);

                while (area_len >= 2) {
                    susp_sl_component_t *component = (void *)cur_su->sl.components + offset;
                    if (component->length > area_len) break;

                    void *cdata = component->data;
                    size_t clen = component->length;

                    if (component->flags & SUSP_SL_CURRENT) {
                        cdata = ".";
                        clen = 1;
                    } else if (component->flags & SUSP_SL_PARENT) {
                        cdata = "..";
                        clen = 2;
                    } else if (component->flags & SUSP_SL_ROOT) {
                        clen = 0;
                        vmfree(out->sl.target, out->sl.length);
                        out->sl.target = vmalloc(1);
                        out->sl.length = 1;
                        *(char *)out->sl.target = '/';
                    } else if (component->flags & SUSP_SL_MOUNT) {
                        clen = 0;
                        vmfree(out->sl.target, out->sl.length);
                        out->sl.length = vfs_alloc_path(&out->sl.target, fs->base.mountpoint);
                    } else if (component->flags & SUSP_SL_HOSTNAME) {
                        // TODO: Actually get the hostname properly
                        cdata = "<hostname>";
                        clen = 10;
                    }

                    if (clen) {
                        bool add_slash = out->sl.length && !sl_was_continue;

                        size_t tlen = clen + out->sl.length + !!add_slash;
                        char *buffer = vmalloc(tlen);
                        memcpy(buffer, out->sl.target, out->sl.length);
                        if (add_slash) buffer[out->sl.length] = '/';
                        memcpy(buffer + out->sl.length + !!add_slash, cdata, clen);
                        vmfree(out->sl.target, out->sl.length);
                        out->sl.target = buffer;
                        out->sl.length = tlen;
                    }

                    sl_was_continue = component->flags & SUSP_SL_CONTINUE;

                    offset += component->length + offsetof(susp_sl_component_t, data);
                    area_len -= component->length + offsetof(susp_sl_component_t, data);
                }

                break;
            }
            case SUSP_ST: su_size = cur_su->length; break;
            case SUSP_TF:
                out->have_tf_creation = cur_su->tf.flags & SUSP_TF_CREATION;
                out->have_tf_modify = cur_su->tf.flags & SUSP_TF_MODIFY;
                out->have_tf_access = cur_su->tf.flags & SUSP_TF_ACCESS;
                out->have_tf_attributes = cur_su->tf.flags & SUSP_TF_ATTRIBUTES;
                out->have_tf_backup = cur_su->tf.flags & SUSP_TF_BACKUP;
                out->have_tf_expiration = cur_su->tf.flags & SUSP_TF_EXPIRATION;
                out->have_tf_effective = cur_su->tf.flags & SUSP_TF_EFFECTIVE;

                size_t i = 0;
#define GET()                                                                                                          \
    ((cur_su->tf.flags & SUSP_TF_LONG_FORM) ? create_timespec_long(&cur_su->tf.lform[i++])                             \
                                            : create_timespec(&cur_su->tf.sform[i++]))
#define GETN(name)                                                                                                     \
    if (out->have_tf_##name) out->tf.name = GET();
                GETN(creation);
                GETN(modify);
                GETN(access);
                GETN(attributes);
                GETN(backup);
                GETN(expiration);
                GETN(effective);
#undef GETN
#undef GET
                break;
            }

            su_size -= cur_su->length;
            cur_su = (void *)cur_su + cur_su->length;
        }

        if (!ce_field) break;

        su_size = ce_field->ce.length.le;

        size_t block_mask = (1ul << fs->device->block_shift) - 1;
        size_t new_alloc_size = (ce_field->ce.offset.le + su_size + block_mask) & ~block_mask;
        void *new_alloc_area = vmalloc(new_alloc_size);
        cur_su = new_alloc_area + ce_field->ce.offset.le;

        int error = fs->device->ops->rvirt(
                fs->device,
                new_alloc_area,
                (uint64_t)ce_field->ce.location.le << (fs->block_shift - fs->device->block_shift),
                new_alloc_size >> fs->device->block_shift
        );
        vmfree(alloc_area, alloc_size);
        if (unlikely(error)) {
            vmfree(new_alloc_area, new_alloc_size);
            return error;
        }

        alloc_area = new_alloc_area;
        alloc_size = new_alloc_size;
    }

    vmfree(alloc_area, alloc_size);
    return 0;
}

static void rr_cleanup(struct rr_info *info) {
    vmfree(info->sl.target, info->sl.length);
}

static int dirino_init(iso9660_fs_t *fs, iso9660_inode_t *inode, struct rr_info *rr_info) {
    if (fs->need_px) return 0;

    uint64_t offset = 0;

    while (offset < inode->base.size) {
        full_dirent_t entry;
        int error = pgcache_read(&inode->base.data, &entry, sizeof(entry), offset);
        if (unlikely(error)) return error;
        if (!entry.common.length) break;

        if (inode->base.ino == INO_BASE && offset == 0) {
            // Check for SUSP presence
            size_t offset = get_susp_off(entry.common.name_length, 0);

            if (offset < entry.common.length && entry.common.length - offset >= 7 &&
                !memcmp((void *)&entry + offset, "SP\x07\x01\xbe\xef", 6)) {
                susp_field_t *field = (void *)&entry + offset;
                fs->rr_skip = field->sp.skip;

                error = get_rr_info(fs, &entry, rr_info);
                if (unlikely(error)) return error;

                if (rr_info->have_px) {
                    fs->need_px = true;
                    return 0;
                }
            }
        }

        // filter out . and ..
        if (entry.common.name_length != 1 || entry.common.name[0] >= 2) {
            if (entry.common.flags & DENT_DIRECTORY) inode->base.nlink += 1;
        }

        offset += entry.common.length;
    }

    return 0;
}

static int create_inode(
        inode_t **out,
        iso9660_fs_t *fs,
        dirent_t *entry,
        ino_t ino,
        extent_t *extents,
        size_t extc,
        uint64_t size,
        struct rr_info *rr_info
) {
    if (fs->need_px && !rr_info->have_px) return EINVAL;

    iso9660_inode_t *inode = vmalloc(sizeof(*inode));
    memset(inode, 0, sizeof(*inode));
    inode->base.ops = &iso9660_inode_ops;
    inode->base.filesystem = &fs->base;
    inode->base.ino = ino;
    inode->base.data.ops = &iso9660_pgcache_ops;
    inode->base.size = size;
    inode->base.blocks = (inode->base.size + (fs->base.block_size - 1)) >> fs->block_shift;

    inode->extents = extents;
    inode->num_extents = extc;
    inode->cur.extent = inode->extents;

    if (entry->flags & DENT_DIRECTORY) {
        inode->base.mode = S_IFDIR | 0555;
        inode->base.nlink = 2;
        inode->base.directory = &iso9660_dir_ops;

        if (!fs->need_px) {
            pgcache_resize(&inode->base.data, inode->base.size);

            int error = dirino_init(fs, inode, rr_info);
            if (unlikely(error)) {
                pgcache_resize(&inode->base.data, 0);
                vmfree(inode, sizeof(*inode));
                return 0;
            }
        }
    } else {
        inode->base.mode = S_IFREG | 0555;
        inode->base.nlink = 1;
    }

    if (rr_info->have_px) {
        inode->base.mode = rr_info->px.mode & 07777;

        switch (rr_info->px.mode & 0170000) {
        case 0010000: inode->base.mode |= S_IFIFO; break;
        case 0020000: inode->base.mode |= S_IFCHR; break;
        case 0040000: inode->base.mode |= S_IFDIR; break;
        case 0060000: inode->base.mode |= S_IFBLK; break;
        case 0100000: inode->base.mode |= S_IFREG; break;
        case 0120000: inode->base.mode |= S_IFLNK; break;
        case 0140000: inode->base.mode |= S_IFSOCK; break;
        }

        if ((entry->flags & DENT_DIRECTORY) && !S_ISDIR(inode->base.mode)) {
            pgcache_resize(&inode->base.data, 0);
            vmfree(inode, sizeof(*inode));
            return EINVAL;
        }

        inode->base.nlink = rr_info->px.nlink;
        inode->base.uid = rr_info->px.uid;
        inode->base.gid = rr_info->px.gid;

        switch (inode->base.mode & S_IFMT) {
        case S_IFBLK:
        case S_IFCHR: inode->base.device = rr_info->pn.dev; break;
        case S_IFLNK:
            inode->base.symlink = rr_info->sl.target;
            inode->base.size = rr_info->sl.length;
            rr_info->sl.target = nullptr; // prevent it from being freed
            break;
        }

        if (rr_info->have_tf_creation) {
            inode->base.atime = rr_info->tf.creation;
            inode->base.ctime = inode->base.atime;
            inode->base.mtime = inode->base.atime;
        }

        if (rr_info->have_tf_access) {
            inode->base.atime = rr_info->tf.access;
            inode->base.ctime = inode->base.atime;
            inode->base.mtime = inode->base.atime;
        }

        if (rr_info->have_tf_modify) {
            inode->base.mtime = rr_info->tf.modify;
            inode->base.ctime = inode->base.mtime;
        }

        if (rr_info->have_tf_attributes) {
            inode->base.ctime = rr_info->tf.attributes;
        }
    } else {
        inode->base.atime = create_timespec(&entry->record_time);
        inode->base.ctime = inode->base.atime;
        inode->base.mtime = inode->base.atime;
    }

    if (S_ISREG(inode->base.mode)) {
        pgcache_resize(&inode->base.data, inode->base.size);
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
        size_t *lout,
        uint64_t *sout
) {
    uint64_t size = 0;
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
        size += entry.extent_len.le;
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
    *sout = size;

    return 0;
}

static int try_dirent(iso9660_fs_t *fs, iso9660_inode_t *self, full_dirent_t *entry, dentry_t *dent, uint64_t offset) {
    struct rr_info rr_info = {};
    int error = get_rr_info(fs, entry, &rr_info);
    if (unlikely(error)) return error;
    if (rr_info.have_rn) goto exit; // skip entries with RE

    void *name;
    size_t len;

    if (rr_info.nm.length) {
        name = rr_info.nm.data;
        len = rr_info.nm.length;
    } else {
        // transform name so that it can be memcmp'd
        len = entry->common.name_length;

        if (!(entry->common.flags & DENT_DIRECTORY)) {
            // get rid of ;<version>
            while (len > 0 && entry->common.name[len - 1] != ';') len--;
            if (len) len--;

            // if there is no extension, get rid of the dot
            if (len > 1 && entry->common.name[len - 1] == '.') len--;
        }

        for (size_t i = 0; i < len; i++) {
            unsigned char c = entry->common.name[i];
            if (c >= 'A' && c <= 'Z') entry->common.name[i] = c + ('a' - 'A');
        }
    }

    if (len == dent->name.length && !memcmp(name, dent->name.data, len)) {
        if (rr_info.have_cl) {
            // get actual data from . entry
            extent_t temp_extent = {
                    rr_info.cl.lba,
                    UINT32_MAX,
            };
            iso9660_inode_t temp_inode = {
                    .base.filesystem = &fs->base,
                    .base.data.ops = &iso9660_pgcache_ops,
                    .extents = &temp_extent,
                    .num_extents = 1,
                    .cur.extent = &temp_extent,
            };
            pgcache_resize(&temp_inode.base.data, sizeof(*entry));
            error = pgcache_read(&temp_inode.base.data, entry, sizeof(*entry), 0);
            pgcache_resize(&temp_inode.base.data, 0);
            if (unlikely(error)) goto exit;
            rr_cleanup(&rr_info);
            error = get_rr_info(fs, entry, &rr_info);
            if (unlikely(error)) return error;
        }

        extent_t *extents;
        size_t ext_count;
        uint64_t size;
        error = get_extent_list(fs, self, entry->common, offset, &extents, &ext_count, &size);
        if (unlikely(error)) goto exit;

        error = create_inode(
                &dent->inode,
                fs,
                &entry->common,
                INO_BASE + (fblock_to_lba(self, offset >> fs->block_shift) << fs->block_shift) + offset,
                extents,
                ext_count,
                size,
                &rr_info
        );
    }

exit:
    rr_cleanup(&rr_info);
    return error;
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
            int error = try_dirent(fs, self, &cur, entry, offset);
            if (unlikely(error)) return error;
            if (entry->inode) return 0;
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
    fs->rr_skip = 0xff;

    extent_t *extents = vmalloc(sizeof(*extents));
    make_extent(fs, extents, &primdesc->primary.root_dirent);

    struct rr_info rr_info = {};
    inode_t *root;
    error = create_inode(
            &root,
            fs,
            &primdesc->primary.root_dirent,
            INO_BASE,
            extents,
            1,
            primdesc->primary.root_dirent.extent_len.le,
            &rr_info
    );
    rr_cleanup(&rr_info);
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
