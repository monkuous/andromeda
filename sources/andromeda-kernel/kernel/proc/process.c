#include "process.h"
#include "compiler.h"
#include "fs/vfs.h"
#include "mem/vmalloc.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "util/container.h"
#include "util/hash.h"
#include "util/list.h"
#include "util/panic.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/wait.h>

#define FD_RESERVED ((void *)1)

procent_t init_procent;

static procent_t **procs;
static size_t proc_capacity;
static size_t proc_count;
static pid_t last_pid;

static procent_t *pidresolve(pid_t pid) {
    if (!proc_capacity) return nullptr;
    if (pid < 0) return nullptr;

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
    if (!ent->has_thread && !ent->has_process && !ent->has_group && !ent->has_session) {
        size_t bucket = make_hash_int32(ent->id) & (proc_capacity - 1);

        if (ent->prev) ent->prev->next = ent->next;
        else procs[bucket] = ent->next;

        if (ent->next) ent->next->prev = ent->prev;

        proc_count -= 1;
    }
}

static inline procent_t *tent(thread_t *thread) {
    return container(procent_t, thread, thread);
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

    init_procent.thread.state = THREAD_RUNNING;
    init_procent.thread.process = &init_process;

    init_procent.process.group = &init_procent.group;
    init_procent.process.nrunning = 1;
    list_insert_tail(&init_procent.process.threads, &current->pnode);

    init_procent.group.session = &init_procent.session;
    list_insert_tail(&init_procent.group.members, &init_procent.process.gnode);

    init_procent.session.members = 1;

    pid_register(&init_procent);
}

pid_t gettid() {
    return tent(current)->id;
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

    if (pgid != 0 && pgid != proc_ent->id) {
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

pid_t pfork(thread_t **thread) {
    process_t *curp = current->process;

    if (last_pid == INT_MAX) return -EAGAIN;

    procent_t *ent = vmalloc(sizeof(*ent));
    memset(ent, 0, sizeof(*ent));

    ent->id = ++last_pid;
    ent->has_thread = true;
    ent->has_process = true;

    ent->process.group = curp->group;
    list_insert_tail(&curp->group->members, &ent->process.gnode);

    ent->process.parent = curp;
    list_insert_tail(&curp->children, &ent->process.pnode);

    ent->process.euid = curp->euid;
    ent->process.ruid = curp->ruid;
    ent->process.suid = curp->suid;
    ent->process.egid = curp->egid;
    ent->process.rgid = curp->rgid;
    ent->process.sgid = curp->sgid;

    memcpy(ent->process.groups, curp->groups, sizeof(curp->groups));
    ent->process.ngroups = curp->ngroups;

    ent->process.cwd = curp->cwd;
    file_ref(ent->process.cwd);
    ent->process.root = curp->root;
    file_ref(ent->process.root);
    ent->process.umask = curp->umask;

    memcpy(ent->process.signal_handlers, curp->signal_handlers, sizeof(curp->signal_handlers));

    size_t fds_size = sizeof(*curp->fds) * curp->fds_cap;
    ent->process.fds = vmalloc(fds_size);
    memcpy(ent->process.fds, curp->fds, fds_size);
    ent->process.fds_cap = curp->fds_cap;
    ent->process.fds_start = curp->fds_start;

    for (size_t i = 0; i < ent->process.fds_cap; i++) {
        struct fd *cur = &ent->process.fds[i];

        if (cur->file == FD_RESERVED) cur->file = nullptr;
        else if (cur->file) file_ref(cur->file);
    }

    ent->thread.process = &ent->process;
    list_insert_tail(&ent->process.threads, &ent->thread.pnode);
    thread_create(&ent->thread, nullptr, nullptr);

    pid_register(ent);

    *thread = &ent->thread;
    return ent->id;
}

pid_t tfork(thread_t **thread) {
    if (last_pid == INT_MAX) return -EAGAIN;

    procent_t *ent = vmalloc(sizeof(*ent));
    memset(ent, 0, sizeof(*ent));

    ent->id = ++last_pid;
    ent->has_thread = true;
    ent->thread.process = current->process;
    list_insert_tail(&current->process->threads, &ent->thread.pnode);
    thread_create(&ent->thread, nullptr, nullptr);

    pid_register(ent);

    *thread = &ent->thread;
    return ent->id;
}

struct waitctx {
    list_node_t node;
    thread_t *thread;
    pid_t pid;
    int options;
    void (*cont)(pid_t, siginfo_t *, void *);
    void *ctx;
    siginfo_t info;
};

static bool is_terminate(int code) {
    return code == CLD_EXITED || code == CLD_KILLED || code == CLD_DUMPED;
}

static bool wait_type_matches(int options, process_t *proc) {
    if ((options & WEXITED) && is_terminate(proc->wa_info.si_code)) return true;
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

        proc->parent->waiting.first = nullptr;
        proc->parent->waiting.last = nullptr;
    }

    procent_t *ent = pent(proc);
    ent->has_process = false;
    maybe_free_procent(ent);
}

static void pwait_cont(void *ptr) {
    struct waitctx *ctx = ptr;

    if (current->wake_reason == WAKE_UNBLOCK) {
        if (ctx->info.si_signo) {
            ctx->cont(ctx->pid, &ctx->info, ctx->ctx);
            // consumption is handled by trigger_wait
        } else {
            ctx->cont(-ECHILD, nullptr, ctx->ctx);
        }
    } else {
        ctx->cont(-EINTR, nullptr, ctx->ctx);
    }

    vmfree(ctx, sizeof(*ctx));
}

static void consume_wait(process_t *parent, process_t *child) {
    child->has_wait = false;
    child->wa_info.si_signo = 0;
    list_remove(&parent->wait_avail, &child->wa_node);
}

pid_t pwait(pid_t pid, int options, void (*cont)(pid_t, siginfo_t *, void *), void *ctx) {
    if (options & ~(WCONTINUED | WEXITED | WNOHANG | WNOWAIT | WSTOPPED)) return -EINVAL;
    if (!(options & (WEXITED | WSTOPPED | WCONTINUED))) return -EINVAL;

    process_t *cproc = current->process;

    if (list_is_empty(&cproc->children)) return ECHILD;

    list_foreach(cproc->wait_avail, process_t, wa_node, child) {
        if (wait_matches(pid, options, cproc, child)) {
            pid_t pid = pent(child)->id;
            cont(pid, &child->wa_info, ctx);

            if (!(options & WNOWAIT)) {
                consume_wait(cproc, child);
                if (list_is_empty(&child->threads)) clean_zombie(child);
            }

            return pid;
        }
    }

    if (options & WNOHANG) return 0;

    struct waitctx *wait = vmalloc(sizeof(*wait));
    memset(wait, 0, sizeof(*wait));
    wait->thread = current;
    wait->pid = pid;
    wait->options = options;
    wait->cont = cont;
    wait->ctx = ctx;

    list_insert_tail(&cproc->waiting, &wait->node);
    sched_block(pwait_cont, wait, true);
    return -EAGAIN;
}

static bool trigger_wait(process_t *proc) {
    ASSERT(proc->wa_info.si_signo == SIGCHLD);

    process_t *parent = proc->parent;

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
                cur->pid = pent(proc)->id;
                cur->info = proc->wa_info;
                sched_unblock(cur->thread);

                if (consume) {
                    consumed = true;
                }
            }

            list_remove(&parent->waiting, &cur->node);
        }

        cur = next;
    }

    if (consumed) {
        consume_wait(parent, proc);
    }

    return consumed;
}

static void make_zombie(process_t *proc) {
    ASSERT(proc->wa_info.si_signo == SIGCHLD);

    // Reparent children
    process_t *cur = container(process_t, pnode, proc->children.first);

    while (cur) {
        process_t *next = container(process_t, pnode, cur->pnode.next);

        cur->parent = &init_process;
        list_insert_tail(&init_process.children, &cur->pnode);

        cur = next;
    }

    leave_group(proc, proc->group);
    file_deref(proc->cwd);
    file_deref(proc->root);
    cleanup_signals(&proc->signals);

    for (size_t i = 0; i < proc->fds_cap; i++) {
        struct fd *fd = &proc->fds[i];

        if (fd->file) {
            file_deref(fd->file);
        }
    }

    vmfree(proc->fds, sizeof(*proc->fds) * proc->fds_cap);

    send_signal(proc->parent, nullptr, &proc->wa_info, false);

    if ((proc->parent->signal_handlers[SIGCHLD].sa_flags & SA_NOCLDWAIT) || trigger_wait(proc)) {
        clean_zombie(proc);
    }
}

void remove_thread_from_process(thread_t *thread) {
    process_t *proc = thread->process;

    list_remove(&proc->threads, &thread->pnode);

    if (list_is_empty(&proc->threads)) {
        make_zombie(proc);
    }
}

void free_thread_struct(thread_t *thread) {
    procent_t *ent = tent(thread);
    ent->has_thread = false;
    maybe_free_procent(ent);
}

int getgroups(int gidsetsize, gid_t grouplist[]) {
    process_t *p = current->process;

    if (gidsetsize == 0) return p->ngroups;
    if (gidsetsize < p->ngroups) return EINVAL;

    memcpy(grouplist, p->groups, p->ngroups * sizeof(*p->groups));
    return p->ngroups;
}

int setegid(gid_t egid) {
    if (egid == (gid_t)-1) return EINVAL;

    process_t *p = current->process;
    if (p->euid != 0 && egid != p->rgid && egid != p->sgid) return EPERM;
    p->egid = egid;
    return 0;
}

int seteuid(uid_t euid) {
    if (euid == (uid_t)-1) return EINVAL;

    process_t *p = current->process;
    if (p->euid != 0 && euid != p->ruid && euid != p->suid) return EPERM;
    p->euid = euid;
    return 0;
}

int setgroups(size_t size, const gid_t list[]) {
    process_t *p = current->process;
    if (p->euid != 0) return EPERM;

    if (size > sizeof(p->groups) / sizeof(*p->groups)) return EINVAL;

    memcpy(p->groups, list, size * sizeof(*p->groups));
    p->ngroups = size;

    return 0;
}

int setregid(gid_t rgid, gid_t egid) {
    process_t *p = current->process;

    if (p->euid != 0) {
        if (rgid != (gid_t)-1 && rgid != p->sgid) return EPERM;
        if (egid != (gid_t)-1 && egid != p->rgid && egid != p->sgid) return EPERM;
    }

    if (rgid != (gid_t)-1) p->rgid = rgid;
    if (egid != (gid_t)-1) p->egid = egid;

    if (rgid != (gid_t)-1 || (egid != (gid_t)-1 && egid != p->rgid)) p->sgid = p->egid;
    return 0;
}

int setreuid(uid_t ruid, uid_t euid) {
    process_t *p = current->process;

    if (p->euid != 0) {
        if (ruid != (uid_t)-1 && ruid != p->suid) return EPERM;
        if (euid != (uid_t)-1 && euid != p->ruid && euid != p->suid) return EPERM;
    }

    if (ruid != (uid_t)-1) p->ruid = ruid;
    if (euid != (uid_t)-1) p->euid = euid;

    if (ruid != (uid_t)-1 || (euid != (uid_t)-1 && euid != p->ruid)) p->suid = p->euid;
    return 0;
}

int setresgid(gid_t rgid, gid_t egid, gid_t sgid) {
    process_t *p = current->process;

    if (p->euid != 0) {
        if (rgid != (gid_t)-1 && rgid != p->rgid && rgid != p->egid && rgid != p->sgid) return EPERM;
        if (egid != (gid_t)-1 && egid != p->rgid && egid != p->egid && egid != p->sgid) return EPERM;
        if (sgid != (gid_t)-1 && sgid != p->rgid && sgid != p->egid && sgid != p->sgid) return EPERM;
    }

    if (rgid != (gid_t)-1) p->rgid = rgid;
    if (egid != (gid_t)-1) p->egid = egid;
    if (sgid != (gid_t)-1) p->sgid = sgid;

    return 0;
}

int setresuid(uid_t ruid, uid_t euid, uid_t suid) {
    process_t *p = current->process;

    if (p->euid != 0) {
        if (ruid != (uid_t)-1 && ruid != p->ruid && ruid != p->euid && ruid != p->suid) return EPERM;
        if (euid != (uid_t)-1 && euid != p->ruid && euid != p->euid && euid != p->suid) return EPERM;
        if (suid != (uid_t)-1 && suid != p->ruid && suid != p->euid && suid != p->suid) return EPERM;
    }

    if (ruid != (uid_t)-1) p->ruid = ruid;
    if (euid != (uid_t)-1) p->euid = euid;
    if (suid != (uid_t)-1) p->suid = suid;

    return 0;
}

int setgid(gid_t gid) {
    if (gid == (gid_t)-1) return EINVAL;

    process_t *p = current->process;

    if (p->euid != 0) {
        if (gid != p->rgid && gid != p->sgid) return EPERM;
        p->egid = gid;
    } else {
        p->rgid = gid;
        p->egid = gid;
        p->sgid = gid;
    }

    return 0;
}

int setuid(uid_t uid) {
    if (uid == (uid_t)-1) return EINVAL;

    process_t *p = current->process;

    if (p->euid != 0) {
        if (uid != p->ruid && uid != p->suid) return EPERM;
        p->euid = uid;
    } else {
        p->ruid = uid;
        p->euid = uid;
        p->suid = uid;
    }

    return 0;
}

relation_t get_relation(uid_t uid, gid_t gid, bool real) {
    process_t *p = current->process;

    if (uid == real ? p->ruid : p->euid) return REL_OWNER;
    if (gid == real ? p->rgid : p->egid) return REL_GROUP;

    for (int i = 0; i < p->ngroups; i++) {
        if (p->groups[i] == gid) return REL_GROUP;
    }

    return REL_OTHER;
}

void kill_other_threads() {
    list_foreach(current->process->threads, thread_t, pnode, cur) {
        if (cur != current) {
            cur->should_exit = true;
            sched_interrupt(cur);
        }
    }
}

void proc_kill(pending_signal_t *trigger) {
    ASSERT(current->process->wa_info.si_signo == 0);
    current->process->wa_info = (siginfo_t){
            .si_signo = SIGCHLD,
            .si_code = CLD_KILLED,
            .si_pid = getpid(),
            .si_uid = trigger->src,
            .si_status = trigger->info.si_signo,
    };

    list_foreach(current->process->threads, thread_t, pnode, cur) {
        cur->should_exit = true;
        sched_interrupt(cur);
    }
}

static bool should_send_sigstopcont() {
    return current->process->parent && !(current->process->parent->signal_handlers[SIGCHLD].sa_flags & SA_NOCLDSTOP);
}

void proc_stop(pending_signal_t *trigger) {
    if (current->process->stopped) return;
    current->process->stopped = true;

    if (should_send_sigstopcont()) {
        ASSERT(current->process->wa_info.si_signo == 0);
        current->process->wa_info = (siginfo_t){
                .si_signo = SIGCHLD,
                .si_code = CLD_STOPPED,
                .si_pid = getpid(),
                .si_uid = trigger->src,
                .si_status = trigger->info.si_signo,
        };
        send_signal(current->process->parent, nullptr, &current->process->wa_info, false);
        trigger_wait(current->process);
    }

    list_foreach(current->process->threads, thread_t, pnode, cur) {
        cur->should_stop = true;
        sched_interrupt(cur);
    }
}

void proc_continue(process_t *proc, pending_signal_t *trigger) {
    if (!proc->stopped) return;
    proc->stopped = false;

    if (trigger && should_send_sigstopcont()) {
        ASSERT(current->process->wa_info.si_signo == 0);
        current->process->wa_info = (siginfo_t){
                .si_signo = SIGCHLD,
                .si_code = CLD_CONTINUED,
                .si_pid = getpid(),
                .si_uid = trigger->src,
                .si_status = trigger->info.si_signo,
        };
        send_signal(current->process->parent, nullptr, &current->process->wa_info, false);
        trigger_wait(current->process);
    }

    list_foreach(proc->threads, thread_t, pnode, cur) {
        if (!cur->should_stop) {
            sched_unblock(cur);
        } else {
            cur->should_stop = false;
        }
    }
}

static void expand_fds(process_t *proc) {
    size_t new_cap = proc->fds_cap ? proc->fds_cap * 2 : 8;
    size_t old_size = sizeof(*proc->fds) * proc->fds_cap;
    size_t new_size = sizeof(*proc->fds) * new_cap;

    void *new_table = vmalloc(new_size);
    memcpy(new_table, proc->fds, old_size);
    memset(new_table + old_size, 0, new_size - old_size);
    vmfree(proc->fds, old_size);

    proc->fds = new_table;
    proc->fds_cap = new_cap;
}

static int do_fd_alloc(unsigned min) {
    process_t *proc = current->process;
    unsigned cur = min >= proc->fds_start ? min : proc->fds_start;

    while (cur != INT_MAX) {
        if (cur >= proc->fds_cap) expand_fds(proc);
        if (cur == proc->fds_start) proc->fds_start += 1;

        if (!proc->fds[cur].file) {
            proc->fds[cur].file = FD_RESERVED;
            return cur;
        }

        cur += 1;
    }

    return -EMFILE;
}

int fd_alloc() {
    return do_fd_alloc(0);
}

void fd_assoc(int fd, file_t *file, int flags) {
    process_t *proc = current->process;
    ASSERT(fd >= 0 && (unsigned)fd < proc->fds_cap);

    struct fd *fds = &proc->fds[fd];
    ASSERT(fds->file == FD_RESERVED);

    fds->file = file;
    fds->flags = flags;
    file_ref(file);
}

void fd_free(int fd) {
    process_t *proc = current->process;
    ASSERT(fd >= 0 && (unsigned)fd < proc->fds_cap);

    struct fd *fds = &proc->fds[fd];
    ASSERT(fds->file);

    if (fds->file != FD_RESERVED) file_deref(fds->file);

    fds->file = nullptr;
    fds->flags = 0;

    if ((unsigned)fd < proc->fds_start) proc->fds_start = fd;
}

int fd_lookup(file_t **out, int fd) {
    process_t *proc = current->process;
    if (unlikely(fd < 0)) return EBADF;
    if (unlikely((unsigned)fd >= proc->fds_cap)) return EBADF;

    file_t *file = proc->fds[fd].file;
    if (unlikely(!file)) return EBADF;
    ASSERT(file != FD_RESERVED);

    *out = file;
    file_ref(file);
    return 0;
}

int fd_free_checked(int fd) {
    process_t *proc = current->process;
    if (unlikely(fd < 0)) return EBADF;
    if (unlikely((unsigned)fd >= proc->fds_cap)) return EBADF;

    struct fd *fds = &proc->fds[fd];
    file_t *file = fds->file;
    if (unlikely(!file)) return EBADF;
    ASSERT(file != FD_RESERVED);

    file_deref(file);
    fds->file = nullptr;
    fds->flags = 0;

    if ((unsigned)fd < proc->fds_start) proc->fds_start = fd;
    return 0;
}

static int do_dupfd(struct fd *fd, int min, int flags) {
    if (unlikely(min < 0)) return -EINVAL;

    int nfd = do_fd_alloc(min);
    if (likely(nfd >= 0)) fd_assoc(nfd, fd->file, flags);

    return nfd;
}

#define VALID_FD_FLAGS (FD_CLOEXEC)

int fd_fcntl(int fd, int cmd, uintptr_t arg) {
    process_t *proc = current->process;
    if (unlikely(fd < 0)) return -EBADF;
    if (unlikely((unsigned)fd >= proc->fds_cap)) return -EBADF;

    struct fd *fds = &proc->fds[fd];
    if (unlikely(!fds->file)) return -EBADF;
    ASSERT(fds->file != FD_RESERVED);

    switch (cmd) {
    case F_DUPFD: return do_dupfd(fds, arg, 0);
    case F_GETFD: return fds->flags;
    case F_SETFD: fds->flags = arg & VALID_FD_FLAGS; return 0;
    case F_GETFL: return fds->file->flags;
    case F_SETFL: fds->file->flags = (fds->file->flags & O_ACCMODE) | (arg & FL_STATUS_FLAGS); return 0;
    case F_DUPFD_CLOEXEC: return do_dupfd(fds, arg, FD_CLOEXEC);
    default: return -EINVAL;
    }
}

int fd_allocassoc(int fd, file_t *file, int flags) {
    if (unlikely(fd < 0)) return EINVAL;
    if (unlikely(fd > INT_MAX)) return EMFILE;

    process_t *proc = current->process;
    while (proc->fds_cap < (unsigned)fd) expand_fds(proc);

    struct fd *fds = &proc->fds[fd];

    if (fds->file) {
        ASSERT(fds->file != FD_RESERVED);
        file_deref(fds->file);
    }

    fds->file = file;
    fds->flags = flags;
    file_ref(file);

    if (proc->fds_start == (unsigned)fd) proc->fds_start++;
    return 0;
}

static bool can_send_signal(process_t *proc, int sig) {
    if (!current->process->euid) return true;
    if (sig == SIGCONT && proc->group->session == current->process->group->session) return true;

    if (current->process->euid == proc->ruid) return true;
    if (current->process->euid == proc->suid) return true;
    if (current->process->ruid == proc->ruid) return true;
    if (current->process->ruid == proc->suid) return true;

    return false;
}

static bool try_sendsig(process_t *proc, int sig) {
    if (!can_send_signal(proc, sig)) return false;

    if (sig && !list_is_empty(&proc->threads)) {
        siginfo_t info = {
                .si_signo = sig,
                .si_code = SI_USER,
                .si_pid = getpid(),
                .si_uid = current->process->ruid,
        };
        send_signal(proc, nullptr, &info, false);
    }

    return true;
}

static int try_sendsig_group(prgroup_t *group, int sig) {
    size_t attempts = 0;
    bool one_sent = false;

    list_foreach(group->members, process_t, gnode, cur) {
        attempts += 1;

        if (try_sendsig(cur, sig)) {
            one_sent = true;
        }
    }

    if (!attempts) return ESRCH;
    if (!one_sent) return EPERM;
    return 0;
}

int proc_sendsig(pid_t pid, int sig) {
    if (unlikely(sig < 0 || sig >= NSIG)) return EINVAL;

    if (pid > 0) {
        procent_t *pent = pidresolve(pid);
        if (unlikely(!pent) || unlikely(!pent->has_process)) return ESRCH;

        if (unlikely(!try_sendsig(&pent->process, sig))) return EPERM;
    } else if (pid == 0) {
        int error = try_sendsig_group(current->process->group, sig);
        if (unlikely(error)) return error;
    } else if (pid < -1) {
        procent_t *pent = pidresolve(-pid);
        if (unlikely(!pent) || unlikely(!pent->has_group)) return ESRCH;

        if (unlikely(!try_sendsig_group(&pent->group, sig))) return EPERM;
    } else {
        // pid == -1
        size_t attempts = 0;
        bool one_sent = false;

        for (size_t i = 0; i < proc_capacity; i++) {
            procent_t *cur = procs[i];

            while (cur) {
                if (cur != &init_procent && cur->has_process) {
                    attempts += 1;

                    if (try_sendsig(&cur->process, sig)) {
                        one_sent = true;
                    }
                }

                cur = cur->next;
            }
        }

        if (!attempts) return ESRCH;
        if (!one_sent) return EPERM;
    }

    return 0;
}
