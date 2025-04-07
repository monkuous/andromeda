#pragma once

#include "fs/vfs.h"
#include "klimits.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "util/list.h"
#include <signal.h> /* IWYU pragma: keep */
#include <sys/types.h>

typedef struct prgroup prgroup_t;
typedef struct procent procent_t;
typedef struct process process_t;
typedef struct session session_t;

typedef enum {
    REL_OWNER,
    REL_GROUP,
    REL_OTHER,
} relation_t;

struct fd {
    file_t *file;
    int flags;
};

struct sigsuspend_ctx {
    list_node_t node;
    thread_t *thread;
    sigset_t old_mask;
};

struct process {
    prgroup_t *group;
    list_node_t gnode;

    process_t *parent;
    list_node_t pnode;

    list_t children;
    list_t threads;
    size_t nrunning;

    list_t sigsuspends;

    uid_t euid;
    uid_t ruid;
    uid_t suid;
    gid_t egid;
    gid_t rgid;
    gid_t sgid;

    gid_t groups[NGROUPS_MAX];
    int ngroups;

    file_t *cwd;
    file_t *root;
    mode_t umask;

    signal_target_t signals;
    struct sigaction signal_handlers[NSIG];

    struct fd *fds;
    size_t fds_cap;
    unsigned fds_start;

    list_t waiting;    // list of active pwait calls
    list_t wait_avail; // list of children with wait info available
    list_node_t wa_node;
    siginfo_t wa_info;

    bool did_exec : 1;
    bool has_wait : 1;
    bool stopped : 1;
    bool owns_tty : 1;
};

struct prgroup {
    session_t *session;
    list_t members;
    // the number of processes whose parent is in a different group within the same sesssion
    size_t orphan_inhibitors;
    size_t num_stopped;
    bool foreground : 1;
};

struct session {
    size_t members;
};

struct procent {
    pid_t id;
    procent_t *prev;
    procent_t *next;

    bool has_thread : 1;
    bool has_process : 1;
    bool has_group : 1;
    bool has_session : 1;

    thread_t thread;
    process_t process;
    prgroup_t group;
    session_t session;
};

extern procent_t init_procent;
#define init_process (init_procent.process)

void init_proc();

pid_t gettid();
pid_t getpgid(pid_t pid);
pid_t getpid();
pid_t getppid();
pid_t getsid(pid_t pid);

int setpgid(pid_t pid, pid_t pgid);
pid_t setsid();

int proc_getgroups(size_t gidsetsize, gid_t grouplist[]);

int setegid(gid_t egid);
int seteuid(uid_t euid);
int proc_setgroups(size_t size, const gid_t list[]);
int setregid(gid_t rgid, gid_t egid);
int setreuid(uid_t ruid, uid_t euid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setgid(gid_t gid);
int setuid(uid_t uid);

relation_t get_relation(uid_t uid, gid_t gid, bool real);

// forks the current process and creates a new thread in it
pid_t pfork(thread_t **thread);

// forks the current thread
pid_t tfork(thread_t **thread);

// Allowed to yield.
pid_t pwait(pid_t pid, int options, void (*cont)(pid_t, siginfo_t *, void *), void *ctx);

void remove_thread_from_process(thread_t *thread);
void free_thread_struct(thread_t *thread);

void kill_other_threads();
void proc_kill(pending_signal_t *trigger);
void proc_stop(pending_signal_t *trigger);
void proc_continue(process_t *proc, pending_signal_t *trigger);

int fd_alloc();
void fd_assoc(int fd, file_t *file, int flags);
void fd_free(int fd);
int fd_lookup(file_t **out, int fd);
int fd_free_checked(int fd);

int fd_fcntl(int fd, int cmd, uintptr_t arg);

int fd_allocassoc(int fd, file_t *file, int flags);

bool can_send_signal(process_t *proc, int sig);
int proc_sendsig(pid_t pid, int sig);

bool is_session_leader(process_t *proc);
pid_t get_pgid(prgroup_t *group);
prgroup_t *resolve_pgid(pid_t pid);
void group_signal(prgroup_t *group, siginfo_t *sig);
pid_t get_sid(session_t *session);
process_t *get_session_leader(session_t *session);

process_t *resolve_pid(pid_t pid);
thread_t *resolve_tid(pid_t tid);
pid_t proc_to_pid(process_t *proc);
