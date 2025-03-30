#include "vfs.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/pgcache.h"
#include "klimits.h"
#include "mem/pmem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "string.h"
#include "util/hash.h"
#include "util/panic.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define OPEN_FLAGS (O_CLOEXEC | O_CREAT | O_DIRECTORY | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_TRUNC | O_PATH)
#define STATUS_FLAGS (O_APPEND | O_DSYNC | O_NONBLOCK | O_RSYNC | O_SYNC)
#define PERM_BITS (S_IRWXU | S_IRWXG | S_IRWXO)
#define MODE_BITS (S_ISUID | S_ISGID | S_ISVTX | PERM_BITS)

static dentry_t root_dentry = {.references = 1};
static fs_t anon_fs = {.device = DEVICE_ID(DRIVER_PSEUDO_FS, 0), .block_size = PAGE_SIZE, .max_name_len = NAME_MAX};
static ino_t anon_ino;

static void maybe_expand(dentry_t *entry) {
    if (entry->count < (entry->capacity - (entry->capacity / 4))) return;

    size_t new_cap = entry->capacity ? entry->capacity * 2 : 8;
    size_t new_size = new_cap * sizeof(*entry->children);
    dentry_t **new_table = vmalloc(new_size);
    memset(new_table, 0, new_size);

    for (size_t i = 0; i < entry->capacity; i++) {
        dentry_t *cur = entry->children[i];

        while (cur) {
            dentry_t *next = cur->next;

            size_t bucket = cur->name.hash & (new_cap - 1);
            cur->prev = nullptr;
            cur->next = new_table[bucket];
            if (cur->next) cur->next->prev = cur;
            new_table[bucket] = cur;

            cur = next;
        }
    }

    vmfree(entry->children, entry->capacity * sizeof(*entry->children));
    entry->children = new_table;
    entry->capacity = new_cap;
}

static void insert_dentry(dentry_t *entry) {
    dentry_t *parent = entry->parent;
    maybe_expand(parent);

    size_t bucket = entry->name.hash & (parent->capacity - 1);

    entry->prev = nullptr;
    entry->next = parent->children[bucket];
    if (entry->next) entry->next->prev = entry;
    parent->children[bucket] = entry;

    parent->count += 1;
    if (entry->inode) parent->pcount += 1;
}

static void remove_dentry(dentry_t *entry) {
    dentry_t *parent = entry->parent;
    size_t bucket = entry->name.hash & (parent->capacity - 1);

    if (entry->prev) entry->prev->next = entry->next;
    else parent->children[bucket] = entry->next;

    if (entry->next) entry->next->prev = entry->prev;

    parent->count -= 1;
    if (entry->inode) parent->pcount -= 1;
}

void dentry_ref(dentry_t *entry) {
    entry->references += 1;
    entry->filesystem->indirect_refs += 1;
}

void dentry_deref(dentry_t *entry) {
    for (;;) {
        entry->filesystem->indirect_refs -= 1;

        if (--entry->references == 0) {
            dentry_t *parent = entry->parent;

            remove_dentry(entry);
            if (entry->inode) inode_deref(entry->inode);
            vmfree(entry, sizeof(*entry));

            if (!parent) break;
            entry = parent;
        } else {
            break;
        }
    }
}

void file_ref(file_t *file) {
    file->references += 1;
}

void file_deref(file_t *file) {
    if (--file->references == 0) {
        if (file->ops->free) file->ops->free(file);

        inode_deref(file->inode);
        if (file->path) dentry_deref(file->path);
        vmfree(file, sizeof(*file));
    }
}

void inode_ref(inode_t *inode) {
    inode->references += 1;
    inode->filesystem->indirect_refs += 1;
}

void inode_deref(inode_t *inode) {
    inode->filesystem->indirect_refs -= 1;

    if (--inode->references == 0) {
        switch (inode->mode & S_IFMT) {
        case S_IFREG: pgcache_resize(&inode->regular, 0); break;
        case S_IFLNK: vmfree(inode->symlink, inode->size); break;
        }

        inode->ops->free(inode);
    }
}

void init_fs(fs_t *fs, inode_t *root) {
    static size_t next_id = 1;

    fs->indirect_refs += 1; /* fs->root */
    fs->id = next_id++;

    fs->root = vmalloc(sizeof(*fs->root));
    memset(fs->root, 0, sizeof(*fs->root));
    fs->root->references = 1;
    fs->root->filesystem = fs;
    fs->root->inode = root;

    inode_ref(root);
}

dev_t next_pseudo_fs_device() {
    static uint32_t next = 1;
    return DEVICE_ID(DRIVER_PSEUDO_FS, next++);
}

void init_inode(fs_t *fs, inode_t *inode) {
    inode->references = 1;
    inode->filesystem = fs;
    fs->indirect_refs += 1;
}

void init_new_inode(fs_t *fs, inode_t *parent, inode_t *inode, mode_t mode, dev_t device) {
    init_inode(fs, inode);

    inode->mode = mode;
    inode->uid = current->process->euid;
    inode->gid = current->process->egid;

    if (parent && (parent->mode & S_ISGID) != 0) {
        inode->gid = parent->gid;
        if (S_ISDIR(mode)) inode->mode |= S_ISGID;
    }

    switch (mode & S_IFMT) {
    case S_IFBLK:
    case S_IFCHR: inode->device = device; break;
    case S_IFDIR: inode->nlink = parent ? 1 : 2; break; // for the . entry (and .. if root)
    }
}

static void anon_inode_free(inode_t *self) {
    vmfree(self, sizeof(*self));
}

static int anon_inode_chmod(inode_t *self, mode_t mode) {
    self->mode = mode;
    return 0;
}

static int anon_inode_chown(inode_t *self, uid_t uid, gid_t gid) {
    if (uid != (uid_t)-1) self->uid = uid;
    if (gid != (gid_t)-1) self->gid = gid;
    return 0;
}

static const inode_ops_t anon_inode_ops = {
        .free = anon_inode_free,
        .chmod = anon_inode_chmod,
        .chown = anon_inode_chown,
};

inode_t *create_anonymous_inode(mode_t mode, dev_t device) {
    inode_t *inode = vmalloc(sizeof(*inode));
    memset(inode, 0, sizeof(*inode));
    inode->ops = &anon_inode_ops;
    inode->ino = anon_ino++;
    init_new_inode(&anon_fs, nullptr, inode, mode, device);
    return inode;
}

int access_inode(inode_t *inode, int amode, bool real) {
    if (!amode || !(real ? current->process->ruid : current->process->euid)) return 0;

    mode_t mask = 0;

    if (amode & R_OK) mask |= S_IROTH;
    if (amode & W_OK) mask |= S_IWOTH;
    if (amode & X_OK) mask |= S_IXOTH;

    switch (get_relation(inode->uid, inode->gid, real)) {
    case REL_OWNER: mask <<= 6; break;
    case REL_GROUP: mask <<= 3; break;
    case REL_OTHER: break;
    }

    return likely((inode->mode & mask) == mask) ? 0 : EACCES;
}

static int regular_seek(file_t *file, uint64_t *offset, int whence) {
    switch (whence) {
    case SEEK_SET: break;
    case SEEK_CUR: *offset += file->position; break;
    case SEEK_END: *offset += file->inode->size; break;
    default: return EINVAL;
    }

    return 0;
}

static int regular_read(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    size_t remaining = *size;
    size_t available = offset < self->inode->size ? self->inode->size - offset : 0;
    if (remaining > available) remaining = available;

    if (remaining) {
        int error = pgcache_read(&self->inode->regular, buffer, remaining, offset);
        if (unlikely(error)) return error;
    }

    if (update_pos) self->position = offset + remaining;
    *size = remaining;
    return 0;
}

static int regular_write(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    if (self->flags & O_APPEND) offset = self->inode->size;

    size_t remaining = *size;
    size_t total = 0;

    uint64_t end_offset = offset + remaining;
    if (unlikely(end_offset < offset)) end_offset = UINT64_MAX;
    if (unlikely(end_offset > INT64_MAX)) {
        end_offset = INT64_MAX;
        if (unlikely(offset >= end_offset)) return EFBIG;
        remaining = end_offset - offset;
    }

    if (end_offset > self->inode->size) {
        int error = self->inode->ops->regular.truncate(self->inode, end_offset);
        if (unlikely(error)) return error;
        pgcache_resize(&self->inode->regular, end_offset);
    }

    if (remaining) {
        int error = pgcache_write(&self->inode->regular, buffer, remaining, offset);
        if (unlikely(error)) return error;
    }

    if (update_pos) self->position = offset + remaining;
    *size = total;
    return 0;
}

static const file_ops_t regular_file_ops = {
        .seek = regular_seek,
        .read = regular_read,
        .write = regular_write,
};

static int access_file(file_t *file, int amode) {
    int avail;

    switch (file->flags & O_ACCMODE) {
    case O_RDONLY: avail = R_OK; break;
    case O_WRONLY: avail = W_OK; break;
    case O_RDWR: avail = R_OK | W_OK; break;
    default: avail = 0; break;
    }

    return (avail & amode) == amode ? 0 : EACCES;
}

int open_inode(file_t **out, dentry_t *path, inode_t *inode, int flags) {
    file_t *file = vmalloc(sizeof(*file));
    memset(file, 0, sizeof(*file));
    file->references = 1;
    file->path = path;
    file->inode = inode;
    file->flags = flags & (O_ACCMODE | STATUS_FLAGS);

    int error = 0;

    switch (inode->mode & S_IFMT) {
    case S_IFDIR: file->ops = inode->directory; break;
    case S_IFREG:
        file->ops = &regular_file_ops;
        if ((flags & O_TRUNC) && !access_file(file, W_OK) && inode->size != 0) {
            error = inode->ops->regular.truncate(inode, 0);
        }
        break;
    case S_IFBLK: error = open_bdev(inode->device, file, flags); break;
    case S_IFCHR: error = open_cdev(inode->device, file, flags); break;
    default: error = ELOOP; break;
    }

    if (unlikely(error)) {
        vmfree(file, sizeof(*file));
        return error;
    }

    if (path) dentry_ref(path);
    inode_ref(inode);

    *out = file;
    return 0;
}

#define RESOLVE_ALLOW_TRAILING 0x100
#define RESOLVE_FOLLOW_SYMLINKS 0x200
#define RESOLVE_NO_TRAILING_DOT 0x400
#define RESOLVE_MUST_EXIST 0x800
#define RESOLVE_MUST_NOT_EXIST 0x1000
#define RESOLVE_NO_RO_FS 0x2000

static int resolve(dentry_t *rel, const unsigned char *path, size_t length, dentry_t **out, int flags);

// Follows symlinks. Dereferences the input entry, even in error cases.
static int follow_symlinks(dentry_t **entry, int flags) {
    dentry_t *cur = *entry;

    int symlinks = flags & 0xff;

    if (unlikely(symlinks == SYMLOOP_MAX)) {
        dentry_deref(cur);
        return ELOOP;
    }

    while (cur->inode && S_ISLNK(cur->inode->mode)) {
        if (!cur->inode->symlink) {
            int error = cur->inode->ops->symlink.read(cur->inode);
            if (unlikely(error)) {
                dentry_deref(cur);
                return error;
            }
        }

        dentry_t *target;
        int error = resolve(cur->parent, cur->inode->symlink, cur->inode->size, &target, symlinks + 1);
        dentry_deref(cur);
        if (unlikely(error)) return error;

        cur = target;
    }

    *entry = cur;
    return 0;
}

// Sets *entry to the top of its mount stack.
static void mount_top(dentry_t **entry) {
    dentry_t *cur = *entry;

    while (cur->mounted_fs) {
        dentry_t *root = cur->mounted_fs->root;
        dentry_ref(root);
        dentry_deref(cur);
        cur = root;
    }

    *entry = cur;
}

static bool entry_matches(dentry_t *entry, const void *name, size_t length, uint32_t hash) {
    return entry->name.hash == hash && entry->name.length == length && memcmp(entry->name.data, name, length) == 0;
}

static int simple_lookup(dentry_t *dir, const void *name, size_t length, dentry_t **out) {
    uint32_t hash = make_hash_blob(name, length);
    dentry_t *entry;

    if (dir->capacity) {
        size_t bucket = hash & (dir->capacity - 1);
        entry = dir->children[bucket];

        while (entry && !entry_matches(entry, name, length, hash)) {
            entry = entry->next;
        }
    } else {
        entry = nullptr;
    }

    if (entry) {
        dentry_ref(entry);
    } else {
        entry = vmalloc(sizeof(*entry));
        memset(entry, 0, sizeof(*entry));
        entry->references = 1;
        entry->filesystem = dir->filesystem;
        entry->parent = dir;
        entry->name.data = vmalloc(length);
        memcpy(entry->name.data, name, length);
        entry->name.length = length;
        entry->name.hash = hash;

        int error = dir->inode->ops->directory.lookup(dir->inode, entry);
        if (unlikely(error != 0 && error != ENOENT)) return error;

        dentry_ref(dir);
        insert_dentry(entry);
    }

    *out = entry;
    return 0;
}

static int resolve(dentry_t *rel, const unsigned char *path, size_t length, dentry_t **out, int flags) {
    if (length == 0) return ENOENT;

    if (path[0] == '/') {
        path++;
        length--;

        rel = &root_dentry;
        dentry_ref(rel);
        mount_top(&rel);
    } else {
        if (!rel) {
            file_t *file = current->process->cwd;
            if (file->path->inode != file->inode) return ENOENT;
            rel = file->path;
        }

        dentry_ref(rel);
    }

    bool was_dot = false;

    while (length > 0) {
        while (length > 0 && path[0] == '/') {
            path++;
            length--;
        }

        int error = follow_symlinks(&rel, flags);
        if (unlikely(error)) return error;

        if (unlikely(!rel->inode)) {
            if (length == 0 && (flags & RESOLVE_ALLOW_TRAILING)) {
                break;
            }

            dentry_deref(rel);
            return ENOENT;
        }

        if (unlikely(!S_ISDIR(rel->inode->mode))) {
            dentry_deref(rel);
            return ENOTDIR;
        }

        if (!length) break;

        error = access_inode(rel->inode, X_OK, false);
        if (unlikely(error)) {
            dentry_deref(rel);
            return error;
        }

        size_t complen = 1;
        while (complen < length && path[complen] != '/') complen++;

        if (unlikely(complen > NAME_MAX)) {
            dentry_deref(rel);
            return ENAMETOOLONG;
        }

        if (length == 2 && path[0] == '.' && path[1] == '.') {
            dentry_t *cur = rel;
            dentry_ref(cur);

            while (!cur->parent) {
                dentry_t *mountpoint = cur->filesystem->mountpoint;
                if (!mountpoint) break;
                dentry_ref(mountpoint);
                dentry_deref(cur);
                cur = mountpoint;
            }

            if (cur->parent) {
                dentry_deref(rel);
                rel = cur->parent;
                dentry_ref(rel);
                dentry_deref(cur);
            } else {
                // We're at /, so .. == .
                dentry_deref(cur);
            }

            was_dot = true;
        } else if (length != 1 && path[0] != '.') {
            dentry_t *child;
            int error = simple_lookup(rel, path, complen, &child);
            dentry_deref(rel);
            if (unlikely(error)) return error;
            rel = child;
            mount_top(&rel);
            was_dot = false;
        } else {
            was_dot = true;
        }

        path += complen;
        length -= complen;
    }

    if ((flags & RESOLVE_NO_TRAILING_DOT) && unlikely(was_dot)) {
        dentry_deref(rel);
        return EINVAL;
    }

    if (flags & RESOLVE_FOLLOW_SYMLINKS) {
        int error = follow_symlinks(&rel, flags);
        if (unlikely(error)) return error;
    }

    if ((flags & RESOLVE_MUST_EXIST) && unlikely(!rel->inode)) {
        dentry_deref(rel);
        return ENOENT;
    }

    if ((flags & RESOLVE_MUST_NOT_EXIST) && unlikely(rel->inode)) {
        dentry_deref(rel);
        return EEXIST;
    }

    if ((flags & RESOLVE_NO_RO_FS) && unlikely(rel->filesystem->flags & ST_RDONLY)) {
        dentry_deref(rel);
        return EROFS;
    }

    *out = rel;
    return 0;
}

static int fresolve(dentry_t **out, file_t *rel, const void *path, size_t length, int flags) {
    if (rel) {
        if (unlikely(!rel->path || !S_ISDIR(rel->inode->mode))) return ENOTDIR;
        if (unlikely(rel->path->inode != rel->inode)) return ENOENT;

        return resolve(rel->path, path, length, out, flags);
    } else {
        return resolve(nullptr, path, length, out, flags);
    }
}

mode_t vfs_umask(mode_t cmask) {
    mode_t prev = current->process->umask;
    current->process->umask = cmask & PERM_BITS;
    return prev;
}

int vfs_open(file_t **out, file_t *rel, const void *path, size_t length, int flags, mode_t mode) {
    if (unlikely(flags & ~(O_ACCMODE | STATUS_FLAGS | OPEN_FLAGS))) return EINVAL;
    if (unlikely(mode & ~MODE_BITS)) return EINVAL;
    mode &= ~current->process->umask;

    int amode;

    switch (flags & (O_ACCMODE & ~O_PATH)) {
    case O_RDONLY: amode = R_OK; break;
    case O_WRONLY: amode = W_OK; break;
    case O_RDWR: amode = R_OK | W_OK; break;
    default: return EINVAL;
    }

    int rflags = 0;

    if (!(flags & (O_NOFOLLOW | O_EXCL))) rflags |= RESOLVE_FOLLOW_SYMLINKS;
    if ((flags & (O_CREAT | O_DIRECTORY)) == (O_CREAT | O_DIRECTORY)) rflags |= RESOLVE_ALLOW_TRAILING;
    if (!(flags & O_CREAT)) rflags |= RESOLVE_MUST_EXIST;
    if (flags & O_EXCL) rflags |= RESOLVE_MUST_NOT_EXIST;
    if ((amode & W_OK) || (flags & O_TRUNC)) rflags |= RESOLVE_NO_RO_FS;

    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, rflags);
    if (unlikely(error)) return error;

    if (!entry->inode) {
        /* O_CREAT present since RESOLVE_MUST_EXIST must be unset for this to be reached */

        if (flags & O_DIRECTORY) mode |= S_IFDIR;
        else mode |= S_IFREG;

        /* can't use RESOLVE_NO_RO_FS for this because O_CREAT allows files to already exist */
        if (unlikely(entry->filesystem->flags & ST_RDONLY)) {
            error = EROFS;
            goto exit;
        }

        dentry_t *parent = entry->parent;
        ASSERT(parent);

        error = access_inode(parent->inode, W_OK, false);
        if (unlikely(error)) goto exit;

        error = parent->inode->ops->directory.create(parent->inode, entry, mode, 0);
        if (unlikely(error)) goto exit;

        parent->pcount += 1;
    } else {
        if (S_ISDIR(entry->inode->mode)) {
            if ((amode & W_OK) || (flags & (O_CREAT | O_DIRECTORY)) == O_CREAT) {
                error = EISDIR;
                goto exit;
            }
        } else if (flags & O_DIRECTORY) {
            error = ENOTDIR;
            goto exit;
        }

        error = access_inode(entry->inode, amode, false);
        if (unlikely(error)) goto exit;
    }

    ASSERT(entry->inode);
    error = open_inode(out, entry, entry->inode, flags);
exit:
    dentry_deref(entry);
    return error;
}

int vfs_mknod(file_t *rel, const void *path, size_t length, mode_t mode, dev_t dev) {
    if (mode & ~(S_IFMT | MODE_BITS)) return EINVAL;
    mode &= ~current->process->umask;

    switch (mode & S_IFMT) {
    case S_IFDIR:
    case S_IFREG:
    case S_IFIFO: break;
    case S_IFBLK:
    case S_IFCHR:
        if (current->process->euid) return EPERM;
        break;
    default: return EINVAL;
    }

    dentry_t *entry;
    int error = fresolve(
            &entry,
            rel,
            path,
            length,
            RESOLVE_MUST_NOT_EXIST | RESOLVE_NO_RO_FS | (S_ISDIR(mode) ? RESOLVE_ALLOW_TRAILING : 0)
    );
    if (unlikely(error)) return error;

    dentry_t *parent = entry->parent;
    ASSERT(parent);

    error = access_inode(parent->inode, W_OK, false);
    if (unlikely(error)) goto exit;

    error = parent->inode->ops->directory.create(parent->inode, entry, mode, dev);
    if (unlikely(error)) goto exit;

    parent->pcount += 1;
exit:
    dentry_deref(entry);
    return error;
}

int vfs_symlink(file_t *rel, const void *path, size_t length, const void *target, size_t tlen) {
    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, RESOLVE_MUST_NOT_EXIST | RESOLVE_NO_RO_FS);
    if (unlikely(error)) return error;

    dentry_t *parent = entry->parent;
    ASSERT(parent);

    error = access_inode(parent->inode, W_OK, false);
    if (unlikely(error)) goto exit;

    error = parent->inode->ops->directory.symlink(parent->inode, entry, target, tlen);
    if (unlikely(error)) goto exit;

    parent->pcount += 1;
exit:
    dentry_deref(entry);
    return 0;
}

int vfs_link(file_t *rel, const void *path, size_t length, file_t *trel, const void *target, size_t tlen, int flags) {
    if (unlikely(flags & ~AT_SYMLINK_FOLLOW)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, RESOLVE_MUST_NOT_EXIST | RESOLVE_NO_RO_FS);
    if (unlikely(error)) return error;

    dentry_t *tentry;
    error = fresolve(
            &tentry,
            trel,
            target,
            tlen,
            RESOLVE_MUST_EXIST | ((flags & AT_SYMLINK_FOLLOW) ? RESOLVE_FOLLOW_SYMLINKS : 0)
    );
    if (unlikely(error)) goto exit_early;

    if (unlikely(tentry->filesystem != entry->filesystem)) {
        error = EXDEV;
        goto exit;
    }

    if (unlikely(S_ISDIR(tentry->inode->mode))) {
        error = EISDIR;
        goto exit;
    }

    dentry_t *parent = entry->parent;
    ASSERT(parent);

    error = access_inode(parent->inode, W_OK, false);
    if (unlikely(error)) goto exit;

    error = parent->inode->ops->directory.mklink(parent->inode, entry, tentry->inode);
    if (unlikely(error)) goto exit;

    parent->pcount += 1;
exit:
    dentry_deref(tentry);
exit_early:
    dentry_deref(entry);
    return error;
}

int vfs_unlink(file_t *rel, const void *path, size_t length, int flags) {
    if (unlikely(flags & ~AT_REMOVEDIR)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(
            &entry,
            rel,
            path,
            length,
            RESOLVE_MUST_EXIST | RESOLVE_NO_RO_FS | (flags & AT_REMOVEDIR ? RESOLVE_NO_TRAILING_DOT : 0)
    );
    if (unlikely(error)) return error;

    if (S_ISDIR(entry->inode->mode)) {
        if (unlikely(!(flags & AT_REMOVEDIR))) {
            error = EPERM;
            goto exit;
        }

        if (unlikely(entry->pcount)) {
            error = ENOTEMPTY;
            goto exit;
        }
    } else if (unlikely(flags & AT_REMOVEDIR)) {
        error = ENOTDIR;
        goto exit;
    }

    dentry_t *parent = entry->parent;

    if (unlikely(!parent)) {
        error = EBUSY;
        goto exit;
    }

    error = access_inode(parent->inode, W_OK, false);
    if (unlikely(error)) goto exit;

    error = parent->inode->ops->directory.unlink(parent->inode, entry);
    if (unlikely(error)) goto exit;

    parent->pcount -= 1;

exit:
    dentry_deref(entry);
    return error;
}

// returns true if a is an ancestor of b (does not cross filesystem boundaries)
static bool is_ancestor(dentry_t *a, dentry_t *b) {
    while (b) {
        if (a == b) return true;

        b = b->parent;
    }

    return false;
}

int vfs_rename(file_t *rel, const void *path, size_t length, file_t *trel, const void *target, size_t tlen) {
    dentry_t *src;
    int error = fresolve(&src, rel, path, length, RESOLVE_MUST_EXIST | RESOLVE_NO_RO_FS | RESOLVE_NO_TRAILING_DOT);
    if (unlikely(error)) return error;

    dentry_t *sparent = src->parent;

    if (unlikely(!sparent)) {
        error = EBUSY;
        goto exit_early;
    }

    error = access_inode(sparent->inode, W_OK, false);
    if (unlikely(error)) goto exit_early;

    dentry_t *dst;
    error = fresolve(
            &dst,
            trel,
            target,
            tlen,
            RESOLVE_NO_TRAILING_DOT | (S_ISDIR(src->inode->mode) ? RESOLVE_ALLOW_TRAILING : 0)
    );
    if (unlikely(error)) goto exit_early;

    if (src->inode == dst->inode) goto exit; // success, no other action

    if (unlikely(src->filesystem != dst->filesystem)) {
        error = EXDEV;
        goto exit;
    }

    if (is_ancestor(src, dst)) {
        error = EINVAL;
        goto exit;
    }

    dentry_t *dparent = dst->parent;

    if (unlikely(!dparent)) {
        error = EBUSY;
        goto exit;
    }

    error = access_inode(dparent->inode, W_OK, false);
    if (unlikely(error)) goto exit;

    inode_t *dst_inode = dst->inode;

    if (dst_inode) {
        if (S_ISDIR(dst_inode->mode)) {
            if (!S_ISDIR(src->inode->mode)) {
                error = EISDIR;
                goto exit;
            }

            if (dst->pcount) {
                error = ENOTEMPTY;
                goto exit;
            }
        } else if (S_ISDIR(src->inode->mode)) {
            error = ENOTDIR;
            goto exit;
        }
    }

    error = sparent->inode->ops->directory.rename(sparent->inode, src, dparent->inode, dst);
    if (unlikely(error)) goto exit;

    remove_dentry(src);
    remove_dentry(dst);
    if (dst_inode) dparent->pcount -= 1;

    dname_t orig_name = src->name;
    src->parent = dparent;
    src->name = dst->name;

    dst->parent = sparent;
    dst->name = orig_name;

    insert_dentry(src);
    insert_dentry(dst);

exit:
    dentry_deref(dst);
exit_early:
    dentry_deref(src);
    return error;
}

int vfs_mount(file_t *rel, const void *path, size_t length, mount_func_t fsf, void *ctx) {
    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, 0);
    if (unlikely(error)) return error;

    if (entry != &root_dentry) {
        if (unlikely(!entry->inode)) {
            error = ENOENT;
            goto exit;
        }

        if (unlikely(!S_ISDIR(entry->inode->mode))) {
            error = ENOTDIR;
            goto exit;
        }
    }

    if (unlikely(entry->mounted_fs)) {
        error = EBUSY;
        goto exit;
    }

    fs_t *fs;
    error = fsf(&fs, ctx);
    if (unlikely(error)) goto exit;

    ASSERT(!entry->mounted_fs);
    entry->mounted_fs = fs;
    fs->mountpoint = entry;
    dentry_ref(entry);

exit:
    dentry_deref(entry);
    return error;
}

int vfs_unmount(file_t *rel, const void *path, size_t length) {
    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, 0);
    if (unlikely(error)) return error;

    if (unlikely(entry->parent) || unlikely(!entry->filesystem)) {
        error = EINVAL;
        goto exit;
    }

    fs_t *fs = entry->filesystem;

    /* 3 references are allowed: fs->root, fs->root->inode, and entry */
    if (unlikely(fs->indirect_refs > 3)) {
        error = EBUSY;
        goto exit;
    }

    fs->mountpoint->mounted_fs = nullptr;
    dentry_deref(fs->mountpoint);

    dentry_deref(fs->root);
    dentry_deref(entry);
    ASSERT(fs->indirect_refs == 0);
    fs->ops->free(fs);

    return 0;

exit:
    dentry_deref(entry);
    return error;
}

int vfs_chdir(file_t *file) {
    if (unlikely(!file->path || !S_ISDIR(file->inode->mode))) return ENOTDIR;

    int error = access_inode(file->inode, X_OK, false);
    if (unlikely(error)) return error;

    file_t *old = current->process->cwd;
    file_ref(file);
    current->process->cwd = file;
    file_deref(old);

    return 0;
}

int vfs_access(file_t *rel, const void *path, size_t length, int amode, int flags) {
    if (unlikely(amode & ~(R_OK | W_OK | X_OK))) return EINVAL;
    if (unlikely(flags & ~AT_EACCESS)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, RESOLVE_MUST_EXIST | RESOLVE_FOLLOW_SYMLINKS);
    if (unlikely(error)) return error;

    error = access_inode(entry->inode, amode, !(flags & AT_EACCESS));
    dentry_deref(entry);
    return error;
}

int vfs_readlink(file_t *rel, const void *path, size_t length, void *buf, size_t *buf_len) {
    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, RESOLVE_MUST_EXIST);
    if (unlikely(error)) return error;

    if (unlikely(!S_ISLNK(entry->inode->mode))) {
        error = EINVAL;
        goto exit;
    }

    if (!entry->inode->symlink) {
        error = entry->inode->ops->symlink.read(entry->inode);
        if (unlikely(error)) goto exit;
    }

    size_t len = *buf_len;
    if (len > entry->inode->size) len = entry->inode->size;

    memcpy(buf, entry->inode->symlink, len); // TODO: Use user_memcpy
    *buf_len = len;

exit:
    dentry_deref(entry);
    return error;
}

static int do_stat(inode_t *inode, struct stat *out) {
    struct stat buf = {
            .st_dev = inode->filesystem->device,
            .st_mode = inode->mode,
            .st_nlink = inode->nlink,
            .st_uid = inode->uid,
            .st_gid = inode->gid,
            .st_size = inode->size,
            .st_blksize = inode->filesystem->block_size,
            .st_blocks = inode->filesystem->blocks,
            .st_ino = inode->ino,
            .st_atim = inode->atime,
            .st_ctim = inode->ctime,
            .st_mtim = inode->mtime,
    };

    if (S_ISBLK(inode->mode) || S_ISCHR(inode->mode)) {
        buf.st_rdev = inode->device;
    }

    // TODO: Use user_memcpy
    memcpy(out, &buf, sizeof(buf));
    return 0;
}

int vfs_stat(file_t *rel, const void *path, size_t length, struct stat *out, int flags) {
    if (unlikely(flags & ~AT_SYMLINK_NOFOLLOW)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(
            &entry,
            rel,
            path,
            length,
            RESOLVE_MUST_EXIST | (flags & AT_SYMLINK_NOFOLLOW ? 0 : RESOLVE_FOLLOW_SYMLINKS)
    );
    if (unlikely(error)) return error;

    error = do_stat(entry->inode, out);
    dentry_deref(entry);
    return error;
}

int vfs_fstat(file_t *file, struct stat *out) {
    return do_stat(file->inode, out);
}

static int truncate_inode(inode_t *inode, off_t size) {
    if (S_ISDIR(inode->mode)) return EISDIR;
    if (!S_ISREG(inode->mode)) return EINVAL;

    int error = inode->ops->regular.truncate(inode, size);
    if (unlikely(error)) return error;

    pgcache_resize(&inode->regular, size);
    return 0;
}

int vfs_truncate(file_t *rel, const void *path, size_t length, off_t size) {
    if (unlikely(size < 0)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, RESOLVE_MUST_EXIST | RESOLVE_NO_RO_FS | RESOLVE_FOLLOW_SYMLINKS);
    if (unlikely(error)) return error;

    error = access_inode(entry->inode, W_OK, false);
    if (unlikely(error)) goto exit;

    error = truncate_inode(entry->inode, size);
exit:
    dentry_deref(entry);
    return error;
}

int vfs_ftruncate(file_t *file, off_t size) {
    if (unlikely(size < 0)) return EINVAL;

    int error = access_file(file, W_OK);
    if (unlikely(error)) return EBADF;

    return truncate_inode(file->inode, size);
}

static int chown_inode(inode_t *inode, uid_t uid, gid_t gid) {
    if (current->process->euid) {
        if (uid != (uid_t)-1) return EPERM;
        if (gid != (gid_t)-1 && gid != inode->gid && get_relation(-1, gid, false) != REL_GROUP) return EPERM;
    }

    return inode->ops->chown(inode, uid, gid);
}

int vfs_chown(file_t *rel, const void *path, size_t length, uid_t uid, gid_t gid, int flags) {
    if (unlikely(flags & ~AT_SYMLINK_NOFOLLOW)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(
            &entry,
            rel,
            path,
            length,
            RESOLVE_MUST_EXIST | RESOLVE_NO_RO_FS | (flags & AT_SYMLINK_NOFOLLOW ? 0 : RESOLVE_FOLLOW_SYMLINKS)
    );
    if (unlikely(error)) return error;

    error = chown_inode(entry->inode, uid, gid);
    dentry_deref(entry);
    return error;
}

int vfs_fchown(file_t *file, uid_t uid, gid_t gid) {
    return chown_inode(file->inode, uid, gid);
}

static int chmod_inode(inode_t *inode, mode_t mode) {
    if (unlikely(current->process->euid && current->process->euid != inode->uid)) return EPERM;
    return inode->ops->chmod(inode, mode & MODE_BITS);
}

int vfs_chmod(file_t *rel, const void *path, size_t length, mode_t mode, int flags) {
    if (unlikely(flags & ~AT_SYMLINK_NOFOLLOW)) return EINVAL;

    dentry_t *entry;
    int error = fresolve(
            &entry,
            rel,
            path,
            length,
            RESOLVE_MUST_EXIST | RESOLVE_NO_RO_FS | (flags & AT_SYMLINK_NOFOLLOW ? 0 : RESOLVE_FOLLOW_SYMLINKS)
    );
    if (unlikely(error)) return error;

    error = chmod_inode(entry->inode, mode);
    dentry_deref(entry);
    return error;
}

int vfs_fchmod(file_t *file, mode_t mode) {
    return chmod_inode(file->inode, mode);
}

off_t vfs_seek(file_t *file, off_t offset, int whence) {
    if (unlikely(!file->ops->seek)) return -ESPIPE;

    uint64_t pos = (int64_t)offset;
    int error = file->ops->seek(file, &pos, whence);
    if (unlikely(error)) return -error;
    if (unlikely(pos > INT64_MAX)) return -EOVERFLOW;

    file->position = pos;
    return pos;
}

static ssize_t do_rw_op(
        file_t *file,
        void *buffer,
        ssize_t size,
        int amode,
        int (*func)(file_t *, void *, size_t *, uint64_t, bool),
        off_t offset,
        bool update_pos
) {
    if (unlikely(!size)) return 0;
    if (unlikely(offset < 0)) return -EINVAL;
    if (unlikely(!func)) return -ENOSYS;

    int error = access_file(file, amode);
    if (unlikely(error)) return -EBADF;

    size_t rsize = size;
    error = func(file, buffer, &rsize, offset, update_pos);
    if (unlikely(error)) return -error;

    return rsize;
}

ssize_t vfs_read(file_t *file, void *buffer, ssize_t size) {
    return do_rw_op(file, buffer, size, R_OK, file->ops->read, file->position, true);
}

ssize_t vfs_write(file_t *file, const void *buffer, ssize_t size) {
    return do_rw_op(file, (void *)buffer, size, W_OK, file->ops->write, file->position, true);
}

ssize_t vfs_pread(file_t *file, void *buffer, ssize_t size, off_t offset) {
    return do_rw_op(file, buffer, size, R_OK, file->ops->read, offset, false);
}

ssize_t vfs_pwrite(file_t *file, const void *buffer, ssize_t size, off_t offset) {
    return do_rw_op(file, (void *)buffer, size, W_OK, file->ops->write, offset, false);
}
