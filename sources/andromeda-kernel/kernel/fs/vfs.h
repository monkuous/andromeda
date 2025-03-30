#pragma once

#include "fs/pgcache.h"
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/types.h>

typedef struct dentry dentry_t;
typedef struct file file_t;
typedef struct fs fs_t;
typedef struct inode inode_t;

typedef int (*mount_func_t)(fs_t **, void *);

typedef struct {
    unsigned char *data;
    size_t length;
    uint32_t hash;
} dname_t;

struct dentry {
    size_t references;

    fs_t *filesystem;
    dentry_t *parent;
    dentry_t *prev;
    dentry_t *next;

    dname_t name;

    dentry_t **children;
    size_t capacity;
    size_t count;
    size_t pcount; // the number of children with associated inodes

    fs_t *mounted_fs;
    inode_t *inode;
};

typedef struct {
    void (*free)(file_t *self);
    int (*seek)(file_t *self, uint64_t *offset, int whence);
    int (*read)(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos);
    int (*write)(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos);
} file_ops_t;

struct file {
    const file_ops_t *ops;
    size_t references;
    uint64_t position;
    dentry_t *path;
    inode_t *inode;
    int flags;
    void *priv;
};

typedef struct {
    void (*free)(fs_t *self);
} fs_ops_t;

struct fs {
    const fs_ops_t *ops;

    dentry_t *mountpoint;
    dentry_t *root;
    size_t indirect_refs; /* total dentry references + total inode references */

    dev_t device;
    size_t id;
    unsigned long flags; /* ST_RDONLY, ST_NOSUID */
    size_t block_size;
    size_t max_name_len;
    fsblkcnt_t blocks;
    fsblkcnt_t bfree;
    fsfilcnt_t files;
    fsfilcnt_t ffree;
};

typedef struct {
    void (*free)(inode_t *self);
    int (*chmod)(inode_t *self, mode_t mode);
    int (*chown)(inode_t *self, uid_t uid, gid_t gid);
    struct {
        int (*lookup)(inode_t *self, dentry_t *entry);
        int (*mklink)(inode_t *self, dentry_t *entry, inode_t *target);
        int (*unlink)(inode_t *self, dentry_t *entry);
        // remember: dest_entry might already exist!
        // note that simply swapping the inode pointers is not allowed; `entry->inode`
        // must stay the same, and `dest_entry->inode` must become null if it isn't already.
        // if this is violated, things like getcwd and directory-relative resolution break.
        int (*rename)(inode_t *self, dentry_t *entry, inode_t *dest, dentry_t *dest_entry);
        int (*create)(inode_t *self, dentry_t *entry, mode_t mode, dev_t device);
        int (*symlink)(inode_t *self, dentry_t *entry, const void *target, size_t length);
    } directory;
    struct {
        int (*truncate)(inode_t *self, uint64_t size);
    } regular;
    struct {
        // sets self->symlink to a buffer allocated with vmalloc(self->size)
        int (*read)(inode_t *self);
    } symlink;
} inode_ops_t;

struct inode {
    const inode_ops_t *ops;
    size_t references;
    fs_t *filesystem;

    ino_t ino;
    mode_t mode;
    nlink_t nlink;
    uid_t uid;
    gid_t gid;
    uint64_t size;
    struct timespec atime;
    struct timespec ctime;
    struct timespec mtime;
    blkcnt_t blocks;

    pgcache_t data;

    union {
        dev_t device;
        const file_ops_t *directory;
        void *symlink;
    };
};

void dentry_ref(dentry_t *entry);
void dentry_deref(dentry_t *entry);
void file_ref(file_t *file);
void file_deref(file_t *file);
void inode_ref(inode_t *inode);
void inode_deref(inode_t *inode);

void init_fs(fs_t *fs, inode_t *root);
dev_t next_pseudo_fs_device();

void init_inode(fs_t *fs, inode_t *inode);
void init_new_inode(fs_t *fs, inode_t *parent, inode_t *inode, mode_t mode, dev_t device);

int access_inode(inode_t *inode, int amode, bool real);
int access_file(file_t *file, int amode);

inode_t *create_anonymous_inode(mode_t mode, dev_t device);
int open_inode(file_t **out, dentry_t *path, inode_t *inode, int flags);

mode_t vfs_umask(mode_t cmask);
int vfs_open(file_t **out, file_t *rel, const void *path, size_t length, int flags, mode_t mode);
int vfs_mknod(file_t *rel, const void *path, size_t length, mode_t mode, dev_t dev);
int vfs_symlink(file_t *rel, const void *path, size_t length, const void *target, size_t tlen);
int vfs_link(file_t *rel, const void *path, size_t length, file_t *trel, const void *target, size_t tlen, int flags);
int vfs_unlink(file_t *rel, const void *path, size_t length, int flags);
int vfs_rename(file_t *rel, const void *path, size_t length, file_t *trel, const void *target, size_t tlen);

int vfs_mount(file_t *rel, const void *path, size_t length, mount_func_t fs, void *ctx);
int vfs_mvmount(file_t *srel, const void *spath, size_t slen, file_t *drel, const void *dpath, size_t dlen);
int vfs_unmount(file_t *rel, const void *path, size_t length);
int vfs_chdir(file_t *file);
int vfs_chroot(file_t *file);

int vfs_access(file_t *rel, const void *path, size_t length, int amode, int flags);
int vfs_readlink(file_t *rel, const void *path, size_t length, void *buf, size_t *buf_len);
int vfs_stat(file_t *rel, const void *path, size_t length, struct stat *out, int flags);
int vfs_fstat(file_t *file, struct stat *out);

int vfs_truncate(file_t *rel, const void *path, size_t length, off_t size);
int vfs_ftruncate(file_t *file, off_t size);
int vfs_chown(file_t *rel, const void *path, size_t length, uid_t uid, gid_t gid, int flags);
int vfs_fchown(file_t *file, uid_t uid, gid_t gid);
int vfs_chmod(file_t *rel, const void *path, size_t length, mode_t mode, int flags);
int vfs_fchmod(file_t *file, mode_t mode);

off_t vfs_seek(file_t *file, off_t offset, int whence);
ssize_t vfs_read(file_t *file, void *buffer, ssize_t size);
ssize_t vfs_write(file_t *file, const void *buffer, ssize_t size);
ssize_t vfs_pread(file_t *file, void *buffer, ssize_t size, off_t offset);
ssize_t vfs_pwrite(file_t *file, const void *buffer, ssize_t size, off_t offset);

size_t vfs_alloc_path(void **out, dentry_t *entry);
