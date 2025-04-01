#pragma once

#include "cpu/idt.h"
#include "mem/vmm.h"
#include "proc/signal.h"
#include "util/list.h"
#include <stddef.h>

typedef void (*thread_cont_t)(void *ctx);

typedef enum {
    THREAD_CREATED,
    THREAD_RUNNING,
    THREAD_UNINTERRUPTIBLE,
    THREAD_INTERRUPTIBLE,
    THREAD_EXITED,
} thread_state_t;

typedef enum {
    WAKE_UNBLOCK,
    WAKE_INTERRUPT,
} wake_reason_t;

typedef struct thread {
    size_t references;
    list_node_t node;
    thread_state_t state;
    idt_frame_t regs;
    struct {
        thread_cont_t func;
        void *ctx;
    } continuation;
    wake_reason_t wake_reason;
    struct process *process;
    list_node_t pnode;
    signal_target_t signals;
    sigset_t signal_mask;
    stack_t sigstack;
    vm_t *vm;
    bool should_exit : 1;
    bool should_stop : 1;
} thread_t;

extern thread_t *current;

void sched_yield();                                                  // Will yield.
void sched_block(thread_cont_t cont, void *ctx, bool interruptible); // Will yield.
void sched_exit();                                                   // Will yield.

void sched_interrupt(thread_t *thread); // Allowed to yield.
void sched_unblock(thread_t *thread);   // Allowed to yield.

// the thread will not run until sched_unblock is called on it
thread_t *thread_create(thread_cont_t cont, void *ctx);
void thread_ref(thread_t *thread);
void thread_deref(thread_t *thread);
