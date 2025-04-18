#pragma once

#include "cpu/fpu.h"
#include "cpu/idt.h"
#include "mem/vmm.h"
#include "proc/signal.h"
#include "util/list.h"
#include <stddef.h>
#include <stdint.h>

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
    fpu_area_t fpu;
    list_node_t node;
    thread_state_t state;
    idt_frame_t regs;
    uintptr_t tdata;
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
void thread_create(thread_t *thread, thread_cont_t cont, void *ctx);
void thread_free(thread_t *thread);
