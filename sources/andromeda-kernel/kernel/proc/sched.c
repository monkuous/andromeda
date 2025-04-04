#include "sched.h"
#include "cpu/gdt.h"
#include "drv/idle.h"
#include "mem/pmap.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "proc/signal.h"
#include "util/container.h"
#include "util/list.h"
#include "util/panic.h"

static list_t thread_queue;

thread_t *current = &init_procent.thread;

static thread_t *pop_thread() {
    return container(thread_t, node, list_remove_head(&thread_queue));
}

static void do_thread_free(thread_t *thread) {
    if (--thread->vm->references == 0) {
        vm_t *vm = vm_join(thread->vm);
        clean_cur_pmap();
        vm_join(vm);
        vm_free(thread->vm);
    }

    cleanup_signals(&thread->signals);
    free_thread_struct(thread);
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

        do_thread_free(prev);
    } else if (prev->vm != current->vm) {
        switch_pmap(&current->vm->pmap);
    }
}

void sched_yield() {
    thread_t *prev = current;

    if (prev->state == THREAD_RUNNING) {
        list_insert_tail(&thread_queue, &prev->node);
    } else if (prev->state == THREAD_EXITED) {
        remove_thread_from_process(prev);
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
        panic("tried to kill init (%s, status: %d)",
              current->process->wa_info.si_code == CLD_EXITED ? "exited" : "killed",
              current->process->wa_info.si_status);
    }

    current->state = THREAD_EXITED;
    current->process->nrunning -= 1;
    sched_yield();
}

static void do_wake(thread_t *thread, wake_reason_t reason) {
    thread->wake_reason = reason;

    if (thread->state != THREAD_RUNNING) {
        thread->process->nrunning += 1;
        thread->state = THREAD_RUNNING;
        list_insert_tail(&thread_queue, &thread->node);
    }
}

void sched_interrupt(thread_t *thread) {
    if (thread->state == THREAD_INTERRUPTIBLE) {
        do_wake(thread, WAKE_INTERRUPT);
    }
}

void sched_unblock(thread_t *thread) {
    do_wake(thread, WAKE_UNBLOCK);
}

void thread_create(thread_t *thread, thread_cont_t cont, void *ctx) {
    thread->state = THREAD_CREATED;
    thread->continuation.func = cont;
    thread->continuation.ctx = ctx;

    thread->regs = current->regs;
    thread->tdata = current->tdata;

    thread->signal_mask = current->signal_mask;
    thread->sigstack.ss_flags |= SS_DISABLE;

    thread->vm = current->vm;
    thread->vm->references += 1;
}

void thread_free(thread_t *thread) {
    ASSERT(thread->state == THREAD_CREATED);
    remove_thread_from_process(thread);
    do_thread_free(thread);
}
