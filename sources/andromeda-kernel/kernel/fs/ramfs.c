#include "ramfs.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "klimits.h"
#include "mem/vmalloc.h"
#include "string.h"
#include "util/panic.h"
#include <errno.h>
#include <sys/stat.h>

static ino_t ramfs_ino;
static const inode_ops_t ramfs_inode_ops;

static void ramfs_inode_free(inode_t *self) {
    vmfree(self, sizeof(*self));
}

static int ramfs_inode_chmod(inode_t *self, mode_t mode) {
    self->mode = (self->mode & S_IFMT) | mode;
    return 0;
}

static int ramfs_inode_chown(inode_t *self, uid_t uid, gid_t gid) {
    if (uid != (uid_t)-1) self->uid = uid;
    if (gid != (gid_t)-1) self->gid = gid;
    return 0;
}

static int ramfs_inode_dir_lookup(inode_t *, dentry_t *) {
    return ENOENT;
}

static int ramfs_inode_dir_mklink(inode_t *, dentry_t *entry, inode_t *target) {
    entry->inode = target;
    inode_ref(target);
    target->nlink += 1;
    return 0;
}

static int ramfs_inode_dir_unlink(inode_t *self, dentry_t *entry) {
    inode_t *inode = entry->inode;
    inode->nlink -= 1;

    if (S_ISDIR(inode->mode)) {
        if (inode->nlink == 1) {
            // remove the . entry
            inode->nlink = 0;
        }

        self->nlink -= 1; // the .. entry got removed
    }

    inode_deref(inode);
    entry->inode = nullptr;

    dentry_deref(entry); // allow it to be freed
    return 0;
}

static int ramfs_inode_dir_rename(inode_t *, dentry_t *, inode_t *dest, dentry_t *dest_entry) {
    // all the heavy lifting is done by the generic vfs code
    return ramfs_inode_dir_unlink(dest, dest_entry);
}

static int ramfs_inode_dir_create(inode_t *self, dentry_t *entry, mode_t mode, dev_t device) {
    inode_t *inode = vmalloc(sizeof(*inode));
    memset(inode, 0, sizeof(*inode));
    inode->ops = &ramfs_inode_ops;
    inode->ino = ramfs_ino++;
    init_new_inode(self->filesystem, self, inode, mode, device);

    entry->inode = inode;
    inode->nlink += 1;

    if (S_ISDIR(mode)) self->nlink += 1;

    dentry_ref(entry); // keep it around
    return 0;
}

static int ramfs_inode_dir_symlink(inode_t *self, dentry_t *entry, const void *target, size_t length) {
    void *buffer = vmalloc(length);
    memcpy(buffer, target, length); // TODO: Use user_memcpy

    int error = ramfs_inode_dir_create(self, entry, S_IFLNK | S_IRWXU | S_IRWXG | S_IRWXO, 0);
    if (unlikely(error)) {
        vmfree(buffer, length);
        return error;
    }

    entry->inode->symlink = buffer;
    return 0;
}

static int ramfs_inode_reg_truncate(inode_t *self, uint64_t size) {
    self->blocks = (size + PAGE_MASK) >> PAGE_SHIFT;
    self->size = size;
    return 0;
}

static int ramfs_inode_symlink_read(inode_t *) {
    UNREACHABLE();
}

static const inode_ops_t ramfs_inode_ops = {
        .free = ramfs_inode_free,
        .chmod = ramfs_inode_chmod,
        .chown = ramfs_inode_chown,
        .directory.lookup = ramfs_inode_dir_lookup,
        .directory.mklink = ramfs_inode_dir_mklink,
        .directory.unlink = ramfs_inode_dir_unlink,
        .directory.rename = ramfs_inode_dir_rename,
        .directory.create = ramfs_inode_dir_create,
        .directory.symlink = ramfs_inode_dir_symlink,
        .regular.truncate = ramfs_inode_reg_truncate,
        .symlink.read = ramfs_inode_symlink_read,
};

static void ramfs_free(fs_t *self) {
    vmfree(self, sizeof(*self));
}

static const fs_ops_t ramfs_ops = {
        .free = ramfs_free,
};

fs_t *ramfs_create(void *ptr) {
    struct ramfs_create_ctx *ctx = ptr;

    fs_t *fs = vmalloc(sizeof(*fs));
    memset(fs, 0, sizeof(*fs));

    fs->ops = &ramfs_ops;
    fs->device = next_pseudo_fs_device();
    fs->block_size = PAGE_SIZE;
    fs->max_name_len = NAME_MAX;

    inode_t *root = vmalloc(sizeof(*root));
    memset(root, 0, sizeof(*root));
    root->ops = &ramfs_inode_ops;
    root->ino = ramfs_ino++;
    init_new_inode(fs, nullptr, root, S_IFDIR | ctx->mode, 0);

    init_fs(fs, root);
    inode_deref(root);
    return fs;
}
