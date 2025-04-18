#pragma once

#include "compiler.h"
#include "fs/pgcache.h"
#include "util/list.h"
#include "util/panic.h"
#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#define FL_STATUS_FLAGS (O_PATH | O_APPEND | O_DSYNC | O_NONBLOCK | O_RSYNC | O_SYNC)

typedef struct dentry dentry_t;
typedef struct file file_t;
typedef struct fs fs_t;
typedef struct inode inode_t;
typedef struct thread thread_t;

typedef int (*mount_func_t)(fs_t **, void *);

typedef struct {
    list_node_t node; // for use by the implementations of poll_{submit,cancel}
    thread_t *thread; // the thread to unblock when poll status changes
} poll_waiter_t;

typedef struct {
    unsigned char *data;
    size_t length;
    uint32_t hash;
} dname_t;

typedef struct {
    ino_t inode;
    off_t offset;
    unsigned short length;
    unsigned char type;
    unsigned char name[];
} readdir_output_t;

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

    list_t child_list;
    list_node_t node;

    list_node_t lru_node;
    list_node_t fs_node;

    fs_t *mounted_fs;
    inode_t *inode;
};

typedef struct {
    void (*free)(file_t *self);
    int (*seek)(file_t *self, uint64_t *offset, int whence);
    int (*read)(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos);
    int (*write)(file_t *self, void *buffer, size_t *size, uint64_t offset, bool update_pos);
    void (*mmap)(file_t *self, uintptr_t head, uintptr_t tail, uint64_t offset, int flags, int prot);
    int (*ioctl)(file_t *self, unsigned long request, void *arg);
    int (*poll)(file_t *self);
    void (*poll_submit)(file_t *self, poll_waiter_t *waiter);
    void (*poll_cancel)(file_t *self, poll_waiter_t *waiter);
    int (*readdir)(file_t *self, void *buffer, size_t *size);
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
    char name[FSTYPSZ];
    void (*free)(fs_t *self);
} fs_ops_t;

struct fs {
    const fs_ops_t *ops;

    dentry_t *mountpoint;
    dentry_t *root;
    size_t indirect_refs; /* total dentry references + total inode references */
    size_t implicit_refs; /* the number of references that are allowed at unmount */

    list_t dentries;

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

typedef struct {
    list_node_t node;
    thread_t *thread;
    file_t *file;
    int fd_flags;
} fifo_open_wait_ctx_t;

typedef struct {
    void *buffer;
    size_t read_index;
    size_t write_index;
    size_t num_readers;
    size_t num_writers;
    list_t read_waiting;
    list_t write_waiting;
    list_t open_read_waiting;
    list_t open_write_waiting;
    list_t poll_waiting;
    bool has_data;
} fifo_state_t;

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
        fifo_state_t fifo;
    };
};

extern const file_ops_t fifo_ops;

// returns true if any dentries were freed
bool free_a_dentry();

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
int open_inode(file_t **out, dentry_t *path, inode_t *inode, int flags, const file_ops_t *ops);

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
int vfs_statvfs(file_t *rel, const void *path, size_t length, struct statvfs *out);
int vfs_fstatvfs(file_t *file, struct statvfs *out);

off_t vfs_seek(file_t *file, off_t offset, int whence);
ssize_t vfs_read(file_t *file, void *buffer, ssize_t size);
ssize_t vfs_write(file_t *file, const void *buffer, ssize_t size);
ssize_t vfs_pread(file_t *file, void *buffer, ssize_t size, off_t offset);
ssize_t vfs_pwrite(file_t *file, const void *buffer, ssize_t size, off_t offset);
int vfs_ioctl(file_t *file, unsigned long request, void *arg);
ssize_t vfs_readdir(file_t *file, void *buffer, ssize_t size);

size_t vfs_alloc_path(void **out, dentry_t *entry);

dentry_t *vfs_mount_bottom(dentry_t *entry);
dentry_t *vfs_parent(dentry_t *entry);
dentry_t *get_existing_dentry(dentry_t *parent, const void *name, size_t length);
dentry_t *vfs_mount_top(dentry_t *entry);

// logs the contents of the dentry cache, starting at the true root
void dump_vfs_state();

static inline int write_fully(file_t *file, const void *buffer, size_t length) {
    while (length) {
        ssize_t actual = vfs_write(file, buffer, length < 0x7fffffff ? length : 0x7fffffff);
        if (unlikely(actual < 0)) return -actual;

        buffer += actual;
        length -= actual;
    }

    return 0;
}

static inline void write_or_die(file_t *file, const void *buffer, size_t length) {
    int error = write_fully(file, buffer, length);
    if (unlikely(error)) panic("write failed (%d)", error);
}
