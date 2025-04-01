#include "sched.h"
#include "cpu/gdt.h"
#include "drv/idle.h"
#include "mem/pmap.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "proc/signal.h"
#include "string.h"
#include "util/container.h"
#include "util/list.h"
#include "util/panic.h"

static thread_t init_thread = {
        .state = THREAD_RUNNING,
        .process = &init_process,
};
static list_t thread_queue;

thread_t *current = &init_thread;

static thread_t *pop_thread() {
    return container(thread_t, node, list_remove_head(&thread_queue));
}

static void handle_exit(thread_t *thread) {
    remove_thread_from_process(thread);
    thread_deref(thread);
}

static void handle_switch(thread_t *prev) {
    if (prev->tdata != current->tdata) {
        gdt_refresh_tdata();
    }

    if (prev->state == THREAD_EXITED) {
        if (--prev->vm->references == 0) {
            clean_cur_pmap();
            switch_pmap(&current->vm->pmap);
            vm_free(prev->vm);
        } else if (prev->vm != current->vm) {
            switch_pmap(&current->vm->pmap);
        }

        handle_exit(prev);
    } else if (prev->vm != current->vm) {
        switch_pmap(&current->vm->pmap);
    }
}

void sched_yield() {
    thread_t *prev = current;

    if (prev->state == THREAD_RUNNING) {
        list_insert_tail(&thread_queue, &prev->node);
    }

    thread_t *next = pop_thread();

    while (!next) {
        idle_poll_events();
        next = pop_thread();
    }

    ASSERT(next->state == THREAD_RUNNING);

    current = next;
    handle_switch(prev);

    thread_cont_t cont = next->continuation.func;
    next->continuation.func = nullptr;

    if (cont) {
        cont(next->continuation.ctx);
    }
}

void sched_block(thread_cont_t cont, void *ctx, bool interruptible) {
    current->state = interruptible ? THREAD_INTERRUPTIBLE : THREAD_UNINTERRUPTIBLE;
    current->continuation.func = cont;
    current->continuation.ctx = ctx;
    current->process->nrunning -= 1;
    sched_yield();
}

void sched_exit() {
    if (current->process == &init_process && !current->pnode.prev && !current->pnode.next) {
        panic("tried to kill init");
    }

    current->state = THREAD_EXITED;
    current->process->nrunning -= 1;
    sched_yield();
}

static void do_wake(thread_t *thread, wake_reason_t reason) {
    ASSERT(thread->state == THREAD_CREATED || thread->state == THREAD_INTERRUPTIBLE ||
           thread->state == THREAD_UNINTERRUPTIBLE);

    if (thread->state == THREAD_CREATED) {
        thread_ref(thread);
    }

    thread->process->nrunning += 1;

    thread->state = THREAD_RUNNING;
    thread->wake_reason = reason;
    list_insert_tail(&thread_queue, &thread->node);
}

void sched_interrupt(thread_t *thread) {
    if (thread->state == THREAD_INTERRUPTIBLE) {
        do_wake(thread, WAKE_INTERRUPT);
    }
}

void sched_unblock(thread_t *thread) {
    do_wake(thread, WAKE_UNBLOCK);
}

thread_t *thread_create(thread_cont_t cont, void *ctx) {
    thread_t *thread = vmalloc(sizeof(*thread));
    memset(thread, 0, sizeof(*thread));

    thread->references = 1;
    thread->state = THREAD_CREATED;
    thread->continuation.func = cont;
    thread->continuation.ctx = ctx;
    thread->process = current->process;
    list_insert_tail(&current->process->threads, &thread->pnode);

    thread->regs.cs = GDT_SEL_UCODE;
    thread->regs.ds = GDT_SEL_UDATA;
    thread->regs.es = GDT_SEL_UDATA;
    thread->regs.fs = GDT_SEL_UDATA;
    thread->regs.gs = GDT_SEL_TDATA;
    thread->regs.ss = GDT_SEL_UDATA;

    thread->sigstack.ss_flags |= SS_DISABLE;

    thread->vm = current->vm;
    thread->vm->references += 1;

    return thread;
}

void thread_ref(thread_t *thread) {
    thread->references += 1;
}

void thread_deref(thread_t *thread) {
    if (--thread->references == 0) {
        if (thread->state == THREAD_CREATED) {
            remove_thread_from_process(thread);
        }

        cleanup_signals(&thread->signals);
        vmfree(thread, sizeof(*thread));
    }
}
