#pragma once

#include "fs/vfs.h"
#include "klimits.h"
#include "proc/sched.h"
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

struct process {
    prgroup_t *group;
    list_node_t gnode;

    process_t *parent;
    list_node_t pnode;

    list_t children;
    list_t threads;

    uid_t euid;
    uid_t ruid;
    uid_t suid;
    gid_t egid;
    gid_t rgid;
    gid_t sgid;

    gid_t groups[NGROUPS_MAX];
    int ngroups;

    file_t *cwd;
    mode_t umask;

    list_t waiting;    // list of active pwait calls
    list_t wait_avail; // list of children with wait info available
    list_node_t wa_node;
    siginfo_t wa_info;

    bool did_exec : 1;
    bool has_wait : 1;
};

struct prgroup {
    session_t *session;
    list_t members;
};

struct session {
    size_t members;
};

struct procent {
    pid_t id;
    procent_t *prev;
    procent_t *next;

    bool has_process : 1;
    bool has_group : 1;
    bool has_session : 1;
    process_t process;
    prgroup_t group;
    session_t session;
};

extern procent_t init_procent;
#define init_process (init_procent.process)

void init_proc();

pid_t getpgid(pid_t pid);
pid_t getpid();
pid_t getppid();
pid_t getsid(pid_t pid);

int setpgid(pid_t pid, pid_t pgid);
pid_t setsid();

gid_t getegid();
uid_t geteuid();
gid_t getgid();
int getgroups(int gidsetsize, gid_t grouplist[]);
int getresgid(gid_t *restrict rgid, gid_t *restrict egid, gid_t *restrict sgid);
int getresuid(uid_t *restrict ruid, uid_t *restrict euid, uid_t *restrict suid);
uid_t getuid();

int setegid(gid_t egid);
int seteuid(uid_t euid);
int setgroups(size_t size, const gid_t list[]);
int setregid(gid_t rgid, gid_t egid);
int setreuid(uid_t ruid, uid_t euid);
int setresgid(gid_t rgid, gid_t egid, gid_t sgid);
int setresuid(uid_t ruid, uid_t euid, uid_t suid);
int setgid(gid_t gid);
int setuid(uid_t uid);

relation_t get_relation(uid_t uid, gid_t gid);

// forks the current process and makes the given thread join the new process
// the thread must belong to the current process, and must be in THREAD_CREATED
pid_t pfork(thread_t *thread);

// Allowed to yield.
void pwait(pid_t pid, int options, void (*cont)(int, siginfo_t *, void *), void *ctx);

void remove_thread_from_process(thread_t *thread);
