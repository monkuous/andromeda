#pragma once

#include "proc/sched.h"
#include "util/list.h"
#include <signal.h> /* IWYU pragma: keep */
#include <sys/types.h>

typedef struct prgroup prgroup_t;
typedef struct procent procent_t;
typedef struct process process_t;
typedef struct session session_t;

struct process {
    prgroup_t *group;
    list_node_t gnode;

    process_t *parent;
    list_node_t pnode;

    list_t children;
    list_t threads;

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

// forks the current process and makes the given thread join the new process
// the thread must belong to the current process, and must be in THREAD_CREATED
pid_t pfork(thread_t *thread);

// Allowed to yield.
void pwait(pid_t pid, int options, void (*cont)(int, siginfo_t *, void *), void *ctx);

void remove_thread_from_process(thread_t *thread);
