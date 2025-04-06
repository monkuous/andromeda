#pragma once

#include <signal.h> /* IWYU pragma: keep */
#include <stddef.h>
#include <stdint.h>

typedef struct process process_t;
typedef struct thread thread_t;

typedef struct {
    siginfo_t info;
    uid_t src;
    bool force;
} pending_signal_t;

typedef struct {
    pending_signal_t *signals[NSIG];
    size_t num_pending;
} signal_target_t;

void send_signal(process_t *process, thread_t *thread, siginfo_t *info, bool force);

void trigger_signals();
void cleanup_signals(signal_target_t *target);

bool is_masked_or_ignored(unsigned sig);

int return_from_signal();

void sigset_sanitize(sigset_t *set);
void sigset_clear(sigset_t *set, unsigned sig);
void sigset_set(sigset_t *set, unsigned sig);
void sigset_join(sigset_t *set, const sigset_t *extra);
void sigset_cmask(sigset_t *set, const sigset_t *mask);
bool sigset_get(sigset_t *set, unsigned sig);
