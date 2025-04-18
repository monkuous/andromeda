#include "vfs.h"
#include "compiler.h"
#include "drv/device.h"
#include "fs/fifo.h"
#include "fs/pgcache.h"
#include "klimits.h"
#include "mem/pmem.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "string.h"
#include "util/container.h"
#include "util/hash.h"
#include "util/list.h"
#include "util/panic.h"
#include "util/print.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define OPEN_FLAGS (O_CLOEXEC | O_CREAT | O_DIRECTORY | O_EXCL | O_NOCTTY | O_NOFOLLOW | O_TRUNC | O_PATH)
#define PERM_BITS (S_IRWXU | S_IRWXG | S_IRWXO)
#define MODE_BITS (S_ISUID | S_ISGID | S_ISVTX | PERM_BITS)

static dentry_t root_dentry = {.references = 1};
static const fs_ops_t anon_fs_ops = {.name = "anonymous"};
static fs_t anon_fs = {
        .ops = &anon_fs_ops,
        .device = DEVICE_ID(DRIVER_PSEUDO_FS, 0),
        .block_size = PAGE_SIZE,
        .max_name_len = NAME_MAX
};
static ino_t anon_ino = 1;

static list_t dentry_lru;

static void remove_dentry(dentry_t *entry) {
    list_remove(&entry->filesystem->dentries, &entry->fs_node);
    if (entry->inode) entry->filesystem->implicit_refs -= 1;

    dentry_t *parent = entry->parent;
    if (!parent) return;
    entry->filesystem->implicit_refs -= 1; // for parent

    size_t bucket = entry->name.hash & (parent->capacity - 1);

    if (entry->prev) entry->prev->next = entry->next;
    else parent->children[bucket] = entry->next;

    if (entry->next) entry->next->prev = entry->prev;

    parent->count -= 1;
    if (entry->inode) parent->pcount -= 1;

    list_remove(&parent->child_list, &entry->node);
}

static void free_dentry(dentry_t *entry) {
    dentry_t *parent = entry->parent;

    remove_dentry(entry);
    if (entry->inode) inode_deref(entry->inode);
    vmfree(entry->name.data, entry->name.length);
    vmfree(entry->children, sizeof(*entry->children) * entry->capacity);
    vmfree(entry, sizeof(*entry));

    if (parent) dentry_deref(parent);
}

bool free_a_dentry() {
    dentry_t *entry = container(dentry_t, lru_node, list_remove_head(&dentry_lru));
    if (!entry) return false;
    free_dentry(entry);
    return true;
}

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
    list_insert_tail(&entry->filesystem->dentries, &entry->fs_node);
    if (entry->inode) entry->filesystem->implicit_refs += 1;

    dentry_t *parent = entry->parent;
    if (!parent) return;
    entry->filesystem->implicit_refs += 1; // for parent

    maybe_expand(parent);

    size_t bucket = entry->name.hash & (parent->capacity - 1);

    entry->prev = nullptr;
    entry->next = parent->children[bucket];
    if (entry->next) entry->next->prev = entry;
    parent->children[bucket] = entry;

    parent->count += 1;
    if (entry->inode) parent->pcount += 1;

    list_insert_tail(&parent->child_list, &entry->node);
}

void dentry_ref(dentry_t *entry) {
    if (entry->references++ == 0) list_remove(&dentry_lru, &entry->lru_node);
    if (entry->filesystem) entry->filesystem->indirect_refs += 1;
}

void dentry_deref(dentry_t *entry) {
    if (entry->filesystem) entry->filesystem->indirect_refs -= 1;
    if (--entry->references == 0) {
        // TODO: Enable dentry caching by changing this back to list_insert_tail.
        // This is not currently done because, without the ability to reclaim
        // free memory owned by kmalloc, it would result in a giant memory leak.
        // list_insert_tail(&dentry_lru, &entry->lru_node);
        free_dentry(entry);
    }
}

void file_ref(file_t *file) {
    file->references += 1;
}

void file_deref(file_t *file) {
    if (--file->references == 0) {
        if (file->ops && file->ops->free) file->ops->free(file);

        if (S_ISFIFO(file->inode->mode)) {
            if (!access_file(file, R_OK)) {
                if (!--file->inode->fifo.num_readers) fifo_no_readers(file->inode);
            }

            if (!access_file(file, W_OK)) {
                if (!--file->inode->fifo.num_writers) fifo_no_writers(file->inode);
            }
        }

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
        pgcache_resize(&inode->data, 0);

        switch (inode->mode & S_IFMT) {
        case S_IFLNK: vmfree(inode->symlink, inode->size); break;
        case S_IFIFO: vmfree(inode->fifo.buffer, PIPE_BUF); break;
        }

        inode->ops->free(inode);
    }
}

void init_fs(fs_t *fs, inode_t *root) {
    static size_t next_id = 1;

    fs->indirect_refs += 1; /* fs->root */
    fs->implicit_refs = 1;  /* fs->root */
    fs->id = next_id++;

    fs->root = vmalloc(sizeof(*fs->root));
    memset(fs->root, 0, sizeof(*fs->root));
    fs->root->references = 1;
    fs->root->filesystem = fs;
    fs->root->inode = root;

    insert_dentry(fs->root);
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

    if (S_ISFIFO(inode->mode)) {
        fifo_init(inode);
    }
}

void init_new_inode(fs_t *fs, inode_t *parent, inode_t *inode, mode_t mode, dev_t device) {
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

    init_inode(fs, inode);
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
        int error = pgcache_read(&self->inode->data, buffer, remaining, offset);
        if (unlikely(error)) return error;
    }

    if (update_pos) self->position = offset + remaining;
    *size = remaining;
    return 0;
}

static int regular_write(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos) {
    if (self->flags & O_APPEND) offset = self->inode->size;

    size_t remaining = *size;

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
        pgcache_resize(&self->inode->data, end_offset);
    }

    if (remaining) {
        int error = pgcache_write(&self->inode->data, buffer, remaining, offset);
        if (unlikely(error)) return error;
    }

    if (update_pos) self->position = offset + remaining;
    *size = remaining;
    return 0;
}

static int regular_poll(file_t *) {
    return POLLIN | POLLRDNORM | POLLRDBAND | POLLPRI | POLLOUT | POLLWRNORM | POLLWRBAND;
}

static void regular_poll_submit(file_t *, poll_waiter_t *) {
}

static void regular_poll_cancel(file_t *, poll_waiter_t *) {
}

static const file_ops_t regular_file_ops = {
        .seek = regular_seek,
        .read = regular_read,
        .write = regular_write,
        .poll = regular_poll,
        .poll_submit = regular_poll_submit,
        .poll_cancel = regular_poll_cancel
};

int access_file(file_t *file, int amode) {
    int avail;

    switch (file->flags & O_ACCMODE) {
    case O_RDONLY: avail = R_OK; break;
    case O_WRONLY: avail = W_OK; break;
    case O_RDWR: avail = R_OK | W_OK; break;
    default: return EACCES;
    }

    return (avail & amode) == amode ? 0 : EACCES;
}

int open_inode(file_t **out, dentry_t *path, inode_t *inode, int flags, const file_ops_t *ops) {
    file_t *file = vmalloc(sizeof(*file));
    memset(file, 0, sizeof(*file));
    file->references = 1;
    file->path = path;
    file->inode = inode;
    file->flags = flags & (O_ACCMODE | FL_STATUS_FLAGS);

    if (ops) {
        file->ops = ops;
    } else if (!(flags & O_PATH)) {
        int error = 0;

        switch (inode->mode & S_IFMT) {
        case S_IFLNK: error = ELOOP; break;
        case S_IFDIR: file->ops = inode->directory; break;
        case S_IFREG:
            file->ops = &regular_file_ops;
            if ((flags & O_TRUNC) && !access_file(file, W_OK) && inode->size != 0) {
                error = inode->ops->regular.truncate(inode, 0);
            }
            break;
        case S_IFBLK: error = open_bdev(inode->device, file, flags); break;
        case S_IFCHR: error = open_cdev(inode->device, file, flags); break;
        case S_IFIFO:
            file->ops = &fifo_ops;
            bool is_read = !access_file(file, R_OK);
            bool is_write = !access_file(file, W_OK);

            if (is_write) {
                // waiting for a read side is done by sys_OPEN, but we do have to take care of O_NONBLOCK first

                if (!is_read && inode->fifo.num_readers == 0 && (flags & O_NONBLOCK)) {
                    error = ENXIO;
                } else if (inode->fifo.num_writers++ == 0) {
                    list_foreach(inode->fifo.open_read_waiting, fifo_open_wait_ctx_t, node, cur) {
                        sched_unblock(cur->thread);
                    }

                    list_foreach(inode->fifo.poll_waiting, poll_waiter_t, node, cur) {
                        sched_unblock(cur->thread);
                    }
                }
            }

            if (likely(!error) && is_read) {
                // waiting for a write side is done by sys_OPEN

                if (inode->fifo.num_readers++ == 0) {
                    list_foreach(inode->fifo.open_write_waiting, fifo_open_wait_ctx_t, node, cur) {
                        sched_unblock(cur->thread);
                    }
                }
            }

            break;
        default: error = EOPNOTSUPP; break;
        }

        if (unlikely(error)) {
            vmfree(file, sizeof(*file));
            return error;
        }
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
        entry->filesystem->indirect_refs += 1;
    }

    *out = entry;
    return 0;
}

static int resolve(dentry_t *rel, const unsigned char *path, size_t length, dentry_t **out, int flags) {
    if (length == 0) return ENOENT;

    if (path[0] == '/') {
        path++;
        length--;

        if (current->process->root) {
            file_t *file = current->process->root;
            if (file->path->inode != file->inode) return ENOENT;
            rel = file->path;
            dentry_ref(rel);
        } else {
            rel = &root_dentry;
            dentry_ref(rel);
            mount_top(&rel);
        }
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

        if (complen == 2 && path[0] == '.' && path[1] == '.') {
            dentry_t *cur = vfs_parent(rel);

            if (cur != rel) {
                dentry_ref(cur);
                dentry_deref(rel);
                rel = cur;
            }

            was_dot = true;
        } else if (complen != 1 || path[0] != '.') {
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
    if (unlikely(flags & ~(O_ACCMODE | FL_STATUS_FLAGS | OPEN_FLAGS))) return EINVAL;
    if (unlikely(mode & ~MODE_BITS)) return EINVAL;
    mode &= ~current->process->umask;

    int amode;

    switch (flags & (O_ACCMODE & ~O_PATH)) {
    case O_RDONLY: amode = R_OK; break;
    case O_WRONLY: amode = W_OK; break;
    case O_RDWR: amode = R_OK | W_OK; break;
    default: return EINVAL;
    }

    if (flags & O_PATH) flags &= O_PATH | O_CLOEXEC | O_DIRECTORY | O_NOFOLLOW;

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

        entry->filesystem->implicit_refs += 1;
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

        if (!(flags & O_PATH)) {
            error = access_inode(entry->inode, amode, false);
            if (unlikely(error)) goto exit;
        }
    }

    ASSERT(entry->inode);
    error = open_inode(out, entry, entry->inode, flags, nullptr);
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

    entry->filesystem->implicit_refs += 1;
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

    entry->filesystem->implicit_refs += 1;
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

    entry->filesystem->implicit_refs += 1;
    parent->pcount += 1;
exit:
    dentry_deref(tentry);
exit_early:
    dentry_deref(entry);
    return error;
}

static int access_sticky(inode_t *inode, inode_t *file) {
    if (inode->mode & S_ISVTX) {
        if (!current->process->euid) return 0;
        if (current->process->euid == file->uid) return 0;
        if (current->process->euid == inode->uid) return 0;

        return EACCES;
    }

    return access_inode(inode, W_OK, false);
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

    error = access_sticky(parent->inode, entry->inode);
    if (unlikely(error)) goto exit;

    error = parent->inode->ops->directory.unlink(parent->inode, entry);
    if (unlikely(error)) goto exit;

    entry->filesystem->implicit_refs -= 1;
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

    error = access_sticky(sparent->inode, src->inode);
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

    inode_t *dst_inode = dst->inode;

    if (dst_inode) {
        error = access_sticky(dparent->inode, dst_inode);
        if (unlikely(error)) goto exit;

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
    } else {
        error = access_inode(dparent->inode, W_OK, false);
        if (unlikely(error)) goto exit;
    }

    error = sparent->inode->ops->directory.rename(sparent->inode, src, dparent->inode, dst);
    if (unlikely(error)) goto exit;

    remove_dentry(src);
    remove_dentry(dst);

    if (dst_inode) {
        dparent->pcount -= 1;
        dparent->filesystem->implicit_refs -= 1;
    }

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
    if (current->process->euid) return EPERM;

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

static bool is_fs_ancestor(fs_t *a, fs_t *b) {
    while (b) {
        if (a == b) return true;

        b = b->mountpoint->filesystem;
    }

    return false;
}

int vfs_mvmount(file_t *srel, const void *spath, size_t slen, file_t *drel, const void *dpath, size_t dlen) {
    if (current->process->euid) return EPERM;

    dentry_t *sentry;
    int error = fresolve(&sentry, srel, spath, slen, 0);
    if (unlikely(error)) return error;

    if (unlikely(sentry->parent) || unlikely(!sentry->filesystem)) {
        error = EINVAL;
        goto early_exit;
    }

    dentry_t *dentry;
    error = fresolve(&dentry, drel, dpath, dlen, 0);
    if (unlikely(error)) goto early_exit;

    if (unlikely(!dentry->inode)) {
        error = ENOENT;
        goto exit;
    }

    if (unlikely(!S_ISDIR(dentry->inode->mode))) {
        error = ENOTDIR;
        goto exit;
    }

    if (unlikely(dentry->mounted_fs)) {
        error = EBUSY;
        goto exit;
    }

    if (is_fs_ancestor(sentry->filesystem, dentry->filesystem)) {
        error = EINVAL;
        goto exit;
    }

    dentry_t *old_mount = sentry->filesystem->mountpoint;

    sentry->filesystem->mountpoint->mounted_fs = nullptr;
    sentry->filesystem->mountpoint = dentry;
    dentry->mounted_fs = sentry->filesystem;

    dentry_deref(old_mount);
    dentry_ref(dentry);

exit:
    dentry_deref(dentry);
early_exit:
    dentry_deref(sentry);
    return error;
}

int vfs_unmount(file_t *rel, const void *path, size_t length) {
    if (current->process->euid) return EPERM;

    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, 0);
    if (unlikely(error)) return error;

    if (unlikely(entry->parent) || unlikely(!entry->filesystem)) {
        error = EINVAL;
        goto exit;
    }

    if (unlikely(entry->mounted_fs)) {
        error = EBUSY;
        goto exit;
    }

    fs_t *fs = entry->filesystem;

    /* one extra reference is allowed, for entry */
    if (unlikely(fs->indirect_refs > fs->implicit_refs + 1)) {
        error = EBUSY;
        goto exit;
    }

    dentry_t *cur = container(dentry_t, fs_node, fs->dentries.first);

    while (cur) {
        dentry_t *next = container(dentry_t, fs_node, cur->fs_node.next);

        if (!cur->references) {
            list_remove(&dentry_lru, &entry->lru_node);
        } else {
            fs->indirect_refs -= cur->references;
        }

        cur->parent = nullptr;
        free_dentry(cur);

        cur = next;
    }

    ASSERT(fs->indirect_refs == 0);

    fs->mountpoint->mounted_fs = nullptr;
    dentry_deref(fs->mountpoint);
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

int vfs_chroot(file_t *file) {
    if (current->process->euid) return EPERM;
    if (unlikely(!file->path || !S_ISDIR(file->inode->mode))) return ENOTDIR;

    if (current->process->root) {
        file_deref(current->process->cwd);
        file_deref(current->process->root);
    }

    current->process->cwd = file;
    current->process->root = file;
    file_ref(file);
    file_ref(file);

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

    error = user_memcpy(buf, entry->inode->symlink, len);
    if (unlikely(error)) goto exit;

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
            .st_blocks = inode->blocks,
            .st_ino = inode->ino,
            .st_atim = inode->atime,
            .st_ctim = inode->ctime,
            .st_mtim = inode->mtime,
    };

    if (S_ISBLK(inode->mode) || S_ISCHR(inode->mode)) {
        buf.st_rdev = inode->device;
    }

    return user_memcpy(out, &buf, sizeof(buf));
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

    pgcache_resize(&inode->data, size);
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
        if (uid != (uid_t)-1 && uid != inode->uid) return EPERM;
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

static int statvfs_inode(inode_t *inode, struct statvfs *out) {
    fs_t *fs = inode->filesystem;

    struct statvfs value = {
            .f_bsize = fs->block_size,
            .f_blocks = fs->blocks,
            .f_bfree = fs->bfree,
            .f_bavail = fs->bfree,
            .f_files = fs->files,
            .f_ffree = fs->ffree,
            .f_favail = fs->ffree,
            .f_fsid = fs->id,
            .f_flag = fs->flags,
            .f_namemax = fs->max_name_len,
    };
    memcpy(value.f_basetype, fs->ops->name, sizeof(value.f_basetype));

    return -user_memcpy(out, &value, sizeof(value));
}

int vfs_statvfs(file_t *rel, const void *path, size_t length, struct statvfs *out) {
    dentry_t *entry;
    int error = fresolve(&entry, rel, path, length, RESOLVE_MUST_EXIST | RESOLVE_FOLLOW_SYMLINKS);
    if (unlikely(error)) return error;

    error = statvfs_inode(entry->inode, out);
    dentry_deref(entry);
    return error;
}

int vfs_fstatvfs(file_t *file, struct statvfs *out) {
    return statvfs_inode(file->inode, out);
}

off_t vfs_seek(file_t *file, off_t offset, int whence) {
    if (unlikely(!file->ops)) return -EBADF;
    if (unlikely(S_ISDIR(file->inode->mode))) return -EISDIR;
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
    if (unlikely(size < 0)) return -EINVAL;
    if (unlikely(offset < 0)) return -EINVAL;
    if (unlikely(S_ISDIR(file->inode->mode))) return -EISDIR;
    if (unlikely(!func)) return -ENOSYS;

    int error = access_file(file, amode);
    if (unlikely(error)) return -EBADF;

    size_t rsize = size;
    error = func(file, buffer, &rsize, offset, update_pos);
    if (unlikely(error)) return -error;

    return rsize;
}

ssize_t vfs_read(file_t *file, void *buffer, ssize_t size) {
    if (unlikely(!file->ops)) return -EBADF;
    return do_rw_op(file, buffer, size, R_OK, file->ops->read, file->position, true);
}

ssize_t vfs_write(file_t *file, const void *buffer, ssize_t size) {
    if (unlikely(!file->ops)) return -EBADF;
    return do_rw_op(file, (void *)buffer, size, W_OK, file->ops->write, file->position, true);
}

ssize_t vfs_pread(file_t *file, void *buffer, ssize_t size, off_t offset) {
    if (unlikely(!file->ops)) return -EBADF;
    if (unlikely(!file->ops->seek)) return -ESPIPE;
    return do_rw_op(file, buffer, size, R_OK, file->ops->read, offset, false);
}

ssize_t vfs_pwrite(file_t *file, const void *buffer, ssize_t size, off_t offset) {
    if (unlikely(!file->ops)) return -EBADF;
    if (unlikely(!file->ops->seek)) return -ESPIPE;
    return do_rw_op(file, (void *)buffer, size, W_OK, file->ops->write, offset, false);
}

ssize_t vfs_readdir(file_t *file, void *buffer, ssize_t size) {
    if (unlikely(!file->ops)) return -EBADF;
    if (unlikely(!file->ops->readdir)) return -ENOTDIR;
    if (unlikely(size < 0)) return -EINVAL;
    if (unlikely(size == 0)) return 0;
    if (unlikely(file->path->inode != file->inode)) return 0;

    size_t s = size;
    int error = file->ops->readdir(file, buffer, &s);
    if (unlikely(error)) return -error;

    return s;
}

static size_t format_path(unsigned char *buffer, size_t length, dentry_t *entry) {
    size_t tot = 0;

    while (entry) {
        if (entry == current->process->root->path) break;

        if (!entry->parent) {
            entry = entry->filesystem->mountpoint;
            continue;
        }

        if (length > entry->name.length) {
            length -= entry->name.length;
            memcpy(&buffer[length], entry->name.data, entry->name.length);
            buffer[--length] = '/';
        }

        tot += entry->name.length + 1;
        entry = entry->parent;
    }

    if (!tot) {
        if (length) buffer[--length] = '/';
        tot++;
    }

    ASSERT(length == 0);
    return tot;
}

int vfs_ioctl(file_t *file, unsigned long request, void *arg) {
    if (unlikely(!file->ops)) return -EBADF;
    if (unlikely(!file->ops->ioctl)) return -ENOTTY;

    return file->ops->ioctl(file, request, arg);
}

size_t vfs_alloc_path(void **out, dentry_t *entry) {
    size_t length = format_path(nullptr, 0, entry);
    void *buf = vmalloc(length);
    format_path(buf, length, entry);
    *out = buf;
    return length;
}

dentry_t *vfs_parent(dentry_t *entry) {
    dentry_t *orig = entry;

    for (;;) {
        if (entry == current->process->root->path) return orig;
        if (entry->parent) return entry->parent;

        entry = entry->filesystem->mountpoint;
    }
}

dentry_t *get_existing_dentry(dentry_t *parent, const void *name, size_t length) {
    if (!parent->capacity) return nullptr;

    uint32_t hash = make_hash_blob(name, length);
    size_t bucket = hash & (parent->capacity - 1);
    dentry_t *entry = parent->children[bucket];

    while (entry && !entry_matches(entry, name, length, hash)) {
        entry = entry->next;
    }

    return entry;
}

dentry_t *vfs_mount_top(dentry_t *entry) {
    while (entry->mounted_fs) entry = entry->mounted_fs->root;
    return entry;
}

static void print_dent(dentry_t *entry, int level, size_t *total) {
    for (int i = 0; i < level; i++) {
        printk("  ");
    }

    if (entry->filesystem && !entry->parent) {
        printk(">");
    }

    dentry_t *name_entry = entry;
    while (!name_entry->parent && name_entry->filesystem) name_entry = name_entry->filesystem->mountpoint;

    void *name;
    size_t length;

    if (name_entry != &root_dentry) {
        name = name_entry->name.data;
        length = name_entry->name.length;
    } else {
        name = "/";
        length = 1;
    }

    printk("%S (%p, %u refs, inode = %p)\n", name, length, entry, entry->references, entry->inode);
    *total += 1;
}

typedef enum {
    DUMP_DESCENDING,
    DUMP_ASCENDING_FROM_CHILD,
    DUMP_ASCENDING_FROM_MOUNT,
} dump_state_t;

static void process_dent(dentry_t *entry, int level, size_t *total) {
    dump_state_t state = DUMP_DESCENDING;

    while (entry) {
        if (state == DUMP_DESCENDING) {
            print_dent(entry, level, total);

            if (entry->child_list.first) {
                entry = container(dentry_t, node, entry->child_list.first);
                level++;
                continue;
            }

            state = DUMP_ASCENDING_FROM_CHILD;
        }

        if (state == DUMP_ASCENDING_FROM_CHILD && entry->mounted_fs) {
            state = DUMP_DESCENDING;
            entry = entry->mounted_fs->root;
            continue;
        }

        if (entry->node.next) {
            state = DUMP_DESCENDING;
            entry = container(dentry_t, node, entry->node.next);
        } else if (entry->parent) {
            state = DUMP_ASCENDING_FROM_CHILD;
            entry = entry->parent;
            level--;
        } else if (entry->filesystem) {
            state = DUMP_ASCENDING_FROM_MOUNT;
            entry = entry->filesystem->mountpoint;
        } else {
            break;
        }
    }
}

void dump_vfs_state() {
    size_t total = 0;
    process_dent(&root_dentry, 0, &total);
    printk("%u total\n", total);
}
