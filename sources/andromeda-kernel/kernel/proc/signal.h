#pragma once

#include <signal.h> /* IWYU pragma: keep */
#include <stddef.h>
#include <stdint.h>

typedef struct process process_t;
typedef struct thread thread_t;

typedef struct {
    siginfo_t info;
    uid_t src;
} pending_signal_t;

typedef struct {
    pending_signal_t *signals[NSIG];
    size_t num_pending;
} signal_target_t;

void send_signal(process_t *process, thread_t *thread, siginfo_t *info);

void trigger_signals();
void cleanup_signals(signal_target_t *target);

int return_from_signal();
