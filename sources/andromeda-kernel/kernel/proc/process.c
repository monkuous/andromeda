#include "process.h"
#include "compiler.h"
#include "mem/vmalloc.h"
#include "proc/sched.h"
#include "string.h"
#include "util/container.h"
#include "util/hash.h"
#include "util/list.h"
#include "util/panic.h"
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

procent_t init_procent;

static procent_t **procs;
static size_t proc_capacity;
static size_t proc_count;
static pid_t last_pid;

static procent_t *pidresolve(pid_t pid) {
    if (!proc_capacity) return nullptr;

    uint32_t hash = make_hash_int32(pid);
    size_t bucket = hash & (proc_capacity - 1);
    procent_t *cur = procs[bucket];

    while (cur && cur->id != pid) {
        cur = cur->next;
    }

    return cur;
}

static void pid_register(procent_t *ent) {
    // expand when 3/4ths full
    if (proc_count >= proc_capacity - (proc_capacity / 4)) {
        size_t new_cap = proc_capacity ? proc_capacity * 2 : 8;
        size_t new_siz = new_cap * sizeof(*procs);
        procent_t **new_table = vmalloc(new_siz);
        memset(new_table, 0, new_siz);

        for (size_t i = 0; i < proc_capacity; i++) {
            procent_t *cur = procs[i];

            while (cur) {
                procent_t *next = cur->next;

                size_t bucket = make_hash_int32(cur->id) & (proc_capacity - 1);

                cur->prev = nullptr;
                cur->next = new_table[bucket];
                if (cur->next) cur->next->prev = cur;
                new_table[bucket] = cur;

                cur = next;
            }
        }

        vmfree(procs, proc_capacity * sizeof(*procs));
        procs = new_table;
        proc_capacity = new_cap;
    }

    size_t bucket = make_hash_int32(ent->id) & (proc_capacity - 1);
    ent->next = procs[bucket];
    if (ent->next) ent->next->prev = ent;
    procs[bucket] = ent;
}

static void maybe_free_procent(procent_t *ent) {
    if (!ent->has_process && !ent->has_group && !ent->has_session) {
        size_t bucket = make_hash_int32(ent->id) & (proc_capacity - 1);

        if (ent->prev) ent->prev->next = ent->next;
        else procs[bucket] = ent->next;

        if (ent->next) ent->next->prev = ent->prev;

        proc_count -= 1;
    }
}

static inline procent_t *pent(process_t *process) {
    return container(procent_t, process, process);
}

static inline procent_t *gent(prgroup_t *group) {
    return container(procent_t, group, group);
}

static inline procent_t *sent(session_t *session) {
    return container(procent_t, session, session);
}

void init_proc() {
    init_procent.id = ++last_pid;
    init_procent.has_process = true;
    init_procent.has_group = true;
    init_procent.has_session = true;

    init_procent.process.group = &init_procent.group;
    list_insert_tail(&init_procent.process.threads, &current->pnode);

    init_procent.group.session = &init_procent.session;
    list_insert_tail(&init_procent.group.members, &init_procent.process.gnode);

    init_procent.session.members = 1;

    pid_register(&init_procent);
}

pid_t getpgid(pid_t pid) {
    if (pid == 0) {
        return gent(current->process->group)->id;
    }

    procent_t *ent = pidresolve(pid);
    if (unlikely(!ent) || unlikely(!ent->has_process)) return -ESRCH;

    return gent(ent->process.group)->id;
}

pid_t getpid() {
    return pent(current->process)->id;
}

pid_t getppid() {
    process_t *proc = current->process->parent;
    return proc ? pent(proc)->id : 0;
}

pid_t getsid(pid_t pid) {
    if (pid == 0) {
        return sent(current->process->group->session)->id;
    }

    procent_t *ent = pidresolve(pid);
    if (unlikely(!ent) || unlikely(!ent->has_process)) return -ESRCH;

    return sent(ent->process.group->session)->id;
}

static void leave_session([[maybe_unused]] prgroup_t *group, session_t *session) {
    ASSERT(group->session == session);

    if (--session->members == 0) {
        procent_t *ent = sent(session);
        ent->has_session = false;
        maybe_free_procent(ent);
    }
}

static void leave_group(process_t *proc, prgroup_t *group) {
    ASSERT(proc->group == group);

    list_remove(&group->members, &proc->gnode);

    if (list_is_empty(&group->members)) {
        leave_session(group, group->session);

        procent_t *ent = gent(group);
        ent->has_group = false;
        maybe_free_procent(ent);
    }
}

int setpgid(pid_t pid, pid_t pgid) {
    if (pgid < 0) return EINVAL;

    process_t *process = current->process;

    if (pid != 0 && pid != pent(process)->id) {
        procent_t *ent = pidresolve(pid);
        if (unlikely(!ent) || unlikely(!ent->has_process)) return ESRCH;

        if (ent->process.parent != process) return ESRCH;
        if (ent->process.group->session != process->group->session) return EPERM;
        if (ent->process.did_exec) return EACCES;

        process = &ent->process;
    }

    procent_t *proc_ent = pent(process);

    if (sent(process->group->session) == proc_ent) return EPERM;

    prgroup_t *old_group = process->group;
    procent_t *group_ent = proc_ent;

    if (pgid != 0) {
        group_ent = pidresolve(pgid);
        if (unlikely(!group_ent) || unlikely(!group_ent->has_group)) return EPERM;
        if (group_ent->group.session != process->group->session) return EPERM;
    }

    if (group_ent->has_group) {
        if (&group_ent->group == old_group) return 0;
    } else {
        ASSERT(list_is_empty(&group_ent->group.members));
        group_ent->has_group = true;
        group_ent->group.session = old_group->session;
        old_group->session->members += 1;
    }

    leave_group(process, old_group);

    process->group = &group_ent->group;
    list_insert_tail(&group_ent->group.members, &process->gnode);
    return 0;
}

pid_t setsid() {
    process_t *proc = current->process;
    procent_t *ent = pent(proc);

    if (ent->has_group || ent == gent(proc->group)) return -EPERM;
    ASSERT(!ent->has_session);

    leave_group(proc, proc->group);

    ASSERT(ent->session.members == 0);
    ent->has_session = true;
    ent->session.members = 1;

    ASSERT(list_is_empty(&ent->group.members));
    ent->has_group = true;
    ent->group.session = &ent->session;

    proc->group = &ent->group;
    list_insert_tail(&ent->group.members, &proc->gnode);

    return ent->id;
}

pid_t pfork(thread_t *thread) {
    ASSERT(thread != current);
    ASSERT(thread->state == THREAD_CREATED);

    process_t *curp = current->process;
    ASSERT(thread->process == curp);

    if (last_pid == INT_MAX) return -EAGAIN;

    procent_t *ent = vmalloc(sizeof(*ent));
    memset(ent, 0, sizeof(*ent));

    ent->id = ++last_pid;
    ent->has_process = true;

    ent->process.group = curp->group;
    list_insert_tail(&curp->group->members, &ent->process.gnode);

    ent->process.parent = curp;
    list_insert_tail(&curp->children, &ent->process.pnode);

    thread->process = &ent->process;
    list_remove(&curp->threads, &thread->pnode);
    list_insert_tail(&ent->process.threads, &thread->pnode);

    pid_register(&init_procent);

    return ent->id;
}

struct waitctx {
    list_node_t node;
    thread_t *thread;
    pid_t pid;
    int options;
    void (*cont)(int, siginfo_t *, void *);
    void *ctx;
    process_t *proc;
};

static bool wait_type_matches(int options, process_t *proc) {
    if ((options & WEXITED) && proc->wa_info.si_code == CLD_EXITED) return true;
    if ((options & WSTOPPED) && proc->wa_info.si_code == CLD_STOPPED) return true;
    if ((options & WCONTINUED) && proc->wa_info.si_code == CLD_CONTINUED) return true;

    return false;
}

static bool wait_matches(pid_t pid, int options, process_t *parent, process_t *proc) {
    if (!wait_type_matches(options, proc)) return false;

    if (pid == -1) return true;
    if (pid == 0) return proc->group == parent->group;
    if (pid < 0) return gent(proc->group)->id == -pid;

    return pent(proc)->id == pid;
}

static void clean_zombie(process_t *proc) {
    ASSERT(list_is_empty(&proc->threads));

    list_remove(&proc->parent->children, &proc->pnode);

    if (list_is_empty(&proc->parent->children)) {
        // Make all pwait calls error with ECHILD
        struct waitctx *cur = container(struct waitctx, node, proc->parent->waiting.first);

        while (cur) {
            struct waitctx *next = container(struct waitctx, node, cur->node.next);
            sched_unblock(cur->thread);
            cur = next;
        }
    }

    procent_t *ent = pent(proc);
    ent->has_process = false;
    maybe_free_procent(ent);
}

static void pwait_cont(void *ptr) {
    process_t *cproc = current->process;
    struct waitctx *ctx = ptr;

    if (current->wake_reason == WAKE_UNBLOCK) {
        if (ctx->proc) {
            ctx->cont(0, &ctx->proc->wa_info, ctx);
            // consumption is handled by trigger_wait
        } else {
            ctx->cont(ECHILD, nullptr, ctx->ctx);
        }
    } else {
        ctx->cont(EINTR, nullptr, ctx->ctx);
    }

    list_remove(&cproc->waiting, &ctx->node);
    vmfree(ctx, sizeof(*ctx));
}

void pwait(pid_t pid, int options, void (*cont)(int, siginfo_t *, void *), void *ctx) {
    if (options & ~(WCONTINUED | WEXITED | WNOHANG | WNOWAIT | WSTOPPED)) {
        cont(EINVAL, nullptr, ctx);
        return;
    }

    if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) {
        cont(EINVAL, nullptr, ctx);
        return;
    }

    process_t *cproc = current->process;

    if (list_is_empty(&cproc->children)) {
        cont(ECHILD, nullptr, ctx);
        return;
    }

    list_foreach(cproc->wait_avail, process_t, wa_node, child) {
        if (wait_matches(pid, options, cproc, child)) {
            cont(0, &child->wa_info, ctx);

            if (!(options & WNOWAIT)) {
                child->has_wait = false;
                list_remove(&cproc->wait_avail, &child->wa_node);
                if (child->wa_info.si_code == CLD_EXITED) clean_zombie(child);
            }

            return;
        }
    }

    if (options & WNOHANG) {
        siginfo_t info = {};
        cont(0, &info, ctx);
        return;
    }

    struct waitctx *wait = vmalloc(sizeof(*wait));
    memset(wait, 0, sizeof(*wait));
    wait->thread = current;
    wait->pid = pid;
    wait->options = options;
    wait->cont = cont;
    wait->ctx = ctx;

    list_insert_tail(&cproc->waiting, &wait->node);
    sched_block(pwait_cont, wait, true);
}

static bool trigger_wait(process_t *proc) {
    process_t *parent = proc->parent;

    proc->wa_info.si_signo = SIGCHLD;
    proc->wa_info.si_pid = pent(proc)->id;

    if (!proc->has_wait) {
        proc->has_wait = true;
        list_insert_tail(&parent->wait_avail, &proc->wa_node);
    }

    struct waitctx *cur = container(struct waitctx, node, parent->waiting.first);
    bool consumed = false;

    while (cur) {
        struct waitctx *next = container(struct waitctx, node, cur->node.next);

        if (wait_matches(cur->pid, cur->options, parent, proc)) {
            bool consume = !(cur->options & WNOWAIT);

            if (!consume || !consumed) {
                cur->proc = proc;
                sched_unblock(cur->thread);

                if (consume) {
                    consumed = true;
                }
            }
        }

        cur = next;
    }

    if (consumed) {
        proc->has_wait = false;
        list_remove(&parent->wait_avail, &proc->wa_node);
    }

    return consumed;
}

static void make_zombie(process_t *proc) {
    if (proc == &init_process) panic("tried to kill init");

    // Reparent children
    process_t *cur = container(process_t, pnode, proc->children.first);

    while (cur) {
        process_t *next = container(process_t, pnode, cur->pnode.next);

        cur->parent = &init_process;
        list_insert_tail(&init_process.children, &cur->pnode);

        cur = next;
    }

    leave_group(proc, proc->group);

    proc->wa_info.si_code = CLD_EXITED;
    bool should_clean = trigger_wait(proc);

    if (should_clean) clean_zombie(proc);
}

void remove_thread_from_process(thread_t *thread) {
    process_t *proc = thread->process;

    list_remove(&proc->threads, &thread->pnode);

    if (list_is_empty(&proc->threads)) {
        make_zombie(proc);
    }
}
