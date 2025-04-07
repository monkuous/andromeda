#include "signal.h"
#include "compiler.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "string.h"
#include "util/list.h"
#include "util/panic.h"
#include <signal.h> /* IWYU pragma: keep */
#include <stdint.h>

typedef enum {
    SD_TERMINATE,
    SD_IGNORE,
    SD_STOP,
} signal_disp_t;

static signal_disp_t get_default_disposition(int signal) {
    switch (signal) {
    case SIGCHLD:
    case SIGCONT:
    case SIGURG: return SD_IGNORE;
    case SIGSTOP:
    case SIGTSTP:
    case SIGTTIN:
    case SIGTTOU: return SD_STOP;
    default: return SD_TERMINATE;
    }
}

static bool would_trigger_signal(process_t *process, thread_t *thread, int signal, bool force) {
    bool forced = false;

    if (sigset_get(&thread->signal_mask, signal)) {
        if (!force) return false;
        forced = true;
    }

    struct sigaction *handler = &process->signal_handlers[signal];

    if (forced || handler->sa_handler == SIG_DFL) {
        return get_default_disposition(signal) != SD_STOP;
    }

    return handler->sa_handler != SIG_IGN;
}

void send_signal(process_t *process, thread_t *thread, siginfo_t *info, bool force) {
    ASSERT(info->si_signo < NSIG);

    if (!thread) {
        list_foreach(process->sigsuspends, struct sigsuspend_ctx, node, cur) {
            if (would_trigger_signal(process, thread, info->si_signo, force)) {
                thread = cur->thread;
                break;
            }
        }
    }

    signal_target_t *target = thread ? &thread->signals : &process->signals;
    pending_signal_t *buf = target->signals[info->si_signo];

    if (!buf) {
        buf = vmalloc(sizeof(*buf));
        target->signals[info->si_signo] = buf;
        target->num_pending += 1;
    }

    memcpy(&buf->info, info, sizeof(*buf));
    buf->src = current->process->ruid;
    buf->force = force || info->si_signo == SIGKILL || info->si_signo == SIGSTOP;

    if (info->si_signo == SIGCONT) proc_continue(process, buf);

    if (!process->nrunning) {
        if (buf->force) proc_continue(process, nullptr);
        else if (process->stopped) return;

        list_foreach(process->threads, thread_t, pnode, cur) {
            if (cur->state == THREAD_INTERRUPTIBLE) {
                sched_interrupt(cur);
                break;
            }
        }
    }
}

typedef struct {
    uintptr_t a0;
    uintptr_t a1;
    uintptr_t a2;
    siginfo_t info;
    ucontext_t context;
    struct _fpstate fpu;
    bool on_sigstack : 1;
} sigctx_no_ra_t;

typedef struct {
    uintptr_t ra;
    sigctx_no_ra_t rest;
} sigctx_t;

static pending_signal_t *get_pending_signal(signal_target_t *target, bool *was_forced_out) {
    if (!target->num_pending) return nullptr;

    for (int i = 0; i < NSIG; i++) {
        pending_signal_t *sig = target->signals[i];

        if (sig) {
            if (sigset_get(&current->signal_mask, i)) {
                if (sig->force) {
                    if (was_forced_out) *was_forced_out = true;
                    return sig;
                }

                continue;
            }

            return sig;
        }
    }

    return nullptr;
}

static bool try_trigger_signals(signal_target_t *target) {
    bool force_default = false;

retry:
    pending_signal_t *sig = get_pending_signal(target, &force_default);
    if (!sig) return false;
    int i = sig->info.si_signo;

    struct sigaction *action = &current->process->signal_handlers[i];

    if (force_default || action->sa_handler == SIG_DFL) {
        signal_disp_t disp = get_default_disposition(i);

        switch (disp) {
        case SD_TERMINATE: proc_kill(sig); break;
        case SD_IGNORE: break;
        case SD_STOP:
            if (current->process->group->orphan_inhibitors) proc_stop(sig);
            break;
        }
    } else if (action->sa_handler != SIG_IGN) {
        idt_frame_t *regs = &current->regs;

        uintptr_t stack_top;
        bool on_sigstack = false;

        if ((action->sa_flags & SA_ONSTACK) && !(current->sigstack.ss_flags & (SS_ONSTACK | SS_DISABLE))) {
            stack_top = (uintptr_t)current->sigstack.ss_sp + current->sigstack.ss_size;
            current->sigstack.ss_flags |= SS_ONSTACK;
            on_sigstack = true;
        } else {
            stack_top = regs->esp;
        }

        uintptr_t ctx_addr = ((stack_top - (sizeof(sigctx_t) - 4)) & ~15) - 4;
        sigctx_t ctx = {};

        ctx.ra = (uintptr_t)action->sa_restorer;
        ctx.rest.a0 = i;
        ctx.rest.a1 = ctx_addr + offsetof(sigctx_t, rest.info);
        ctx.rest.a2 = ctx_addr + offsetof(sigctx_t, rest.context);
        ctx.rest.on_sigstack = on_sigstack;

        ctx.rest.context.uc_sigmask = current->signal_mask;
        ctx.rest.context.uc_mcontext.gregs[REG_GS] = regs->gs;
        ctx.rest.context.uc_mcontext.gregs[REG_FS] = regs->fs;
        ctx.rest.context.uc_mcontext.gregs[REG_ES] = regs->es;
        ctx.rest.context.uc_mcontext.gregs[REG_DS] = regs->ds;
        ctx.rest.context.uc_mcontext.gregs[REG_EDI] = regs->edi;
        ctx.rest.context.uc_mcontext.gregs[REG_ESI] = regs->esi;
        ctx.rest.context.uc_mcontext.gregs[REG_EBP] = regs->ebp;
        ctx.rest.context.uc_mcontext.gregs[REG_ESP] = regs->esp;
        ctx.rest.context.uc_mcontext.gregs[REG_EBX] = regs->ebx;
        ctx.rest.context.uc_mcontext.gregs[REG_EDX] = regs->edx;
        ctx.rest.context.uc_mcontext.gregs[REG_ECX] = regs->ecx;
        ctx.rest.context.uc_mcontext.gregs[REG_EAX] = regs->eax;
        ctx.rest.context.uc_mcontext.gregs[REG_EIP] = regs->eip;
        ctx.rest.context.uc_mcontext.gregs[REG_CS] = regs->cs;
        ctx.rest.context.uc_mcontext.gregs[REG_EFL] = regs->eflags;
        ctx.rest.context.uc_mcontext.gregs[REG_UESP] = regs->esp;
        ctx.rest.context.uc_mcontext.gregs[REG_SS] = regs->ss;
        ctx.rest.context.uc_mcontext.fpregs = (void *)(ctx_addr + offsetof(sigctx_t, rest.fpu));

        asm volatile("fsave %0" : "+m"(ctx.rest.fpu));

        memcpy(&ctx.rest.info, &sig->info, sizeof(sig->info));

        if (unlikely(user_memcpy((void *)ctx_addr, &ctx, sizeof(ctx)))) {
            // fsave reset the registers to their initial values, restore them again
            asm("frstor %0" ::"m"(ctx.rest.context.uc_mcontext.fpregs));
            if (i == SIGSEGV || i == SIGBUS) force_default = true;
            goto retry;
        }

        sigset_join(&current->signal_mask, &action->sa_mask);
        if (!(action->sa_flags & SA_NODEFER)) sigset_set(&current->signal_mask, i);

        if ((action->sa_flags & SA_RESTART) && regs->vector == 0x20) {
            regs->vector = 0;
            ctx.rest.context.uc_mcontext.gregs[REG_EIP] -= 2;
        }

        regs->eip = (uintptr_t)action->sa_handler;
        regs->esp = ctx_addr;

        if (i != SIGILL && i != SIGTRAP && (action->sa_flags & SA_RESETHAND)) {
            action->sa_handler = nullptr;
            action->sa_flags &= ~SA_SIGINFO;
        }

        asm("fwait");
    }

    target->signals[i] = nullptr;
    target->num_pending -= 1;
    vmfree(sig, sizeof(*sig));
    return true;
}

void trigger_signals() {
    if (!try_trigger_signals(&current->signals)) {
        try_trigger_signals(&current->process->signals);
    }
}

bool will_trigger_signal() {
    pending_signal_t *signal = get_pending_signal(&current->signals, nullptr);
    if (!signal) signal = get_pending_signal(&current->process->signals, nullptr);
    if (!signal) return false;

    return would_trigger_signal(current->process, current, signal->info.si_signo, signal->force);
}

bool is_pending(unsigned sig) {
    if (current->signals.signals[sig]) return true;
    if (current->process->signals.signals[sig]) return true;
    return false;
}

bool is_masked_or_ignored(unsigned sig) {
    ASSERT(sig < NSIG);

    return sigset_get(&current->signal_mask, sig) || current->process->signal_handlers[sig].sa_handler == SIG_IGN ||
           get_default_disposition(sig) == SD_IGNORE;
}

void cleanup_signals(signal_target_t *target) {
    if (!target->num_pending) return;

    for (int i = 0; i < NSIG; i++) {
        if (target->signals[i]) {
            vmfree(target->signals[i], sizeof(*target->signals));
            target->signals[i] = nullptr;
        }
    }

    target->num_pending = 0;
}

static bool is_selector_ok(uint16_t selector, bool code) {
    if (selector & 4) return false;        // don't allow LDT selectors
    if ((selector & 3) == 3) return false; // don't allow rpl != 3

    if (selector < 8) return true; // allow null selectors

    if (code) {
        if (selector == GDT_SEL_UCODE) return true;
    } else {
        if (selector == GDT_SEL_UDATA) return true;
        if (selector == GDT_SEL_TDATA) return true;
    }

    return false;
}

static void sanitize_seg(uint16_t *selptr, bool code, uint16_t def) {
    if (is_selector_ok(*selptr, code)) return;

    *selptr = def;
}

static uint32_t sanitize_eflags(uint32_t flags) {
    // allow RF, OF, DF, TF, SF, ZF, AF, PF, and CF to be controlled by the user
    return (flags & 0x10dd5) | 2;
}

int return_from_signal() {
    idt_frame_t *regs = &current->regs;

    sigctx_no_ra_t ctx;
    int error = user_memcpy(&ctx, (const void *)regs->esp, sizeof(ctx));
    if (unlikely(error)) return error;

    current->signal_mask = ctx.context.uc_sigmask;
    regs->gs = ctx.context.uc_mcontext.gregs[REG_GS];
    regs->fs = ctx.context.uc_mcontext.gregs[REG_FS];
    regs->es = ctx.context.uc_mcontext.gregs[REG_ES];
    regs->ds = ctx.context.uc_mcontext.gregs[REG_DS];
    regs->edi = ctx.context.uc_mcontext.gregs[REG_EDI];
    regs->esi = ctx.context.uc_mcontext.gregs[REG_ESI];
    regs->ebp = ctx.context.uc_mcontext.gregs[REG_EBP];
    regs->ebx = ctx.context.uc_mcontext.gregs[REG_EBX];
    regs->edx = ctx.context.uc_mcontext.gregs[REG_EDX];
    regs->ecx = ctx.context.uc_mcontext.gregs[REG_ECX];
    regs->eax = ctx.context.uc_mcontext.gregs[REG_EAX];
    regs->eip = ctx.context.uc_mcontext.gregs[REG_EIP];
    regs->cs = ctx.context.uc_mcontext.gregs[REG_CS];
    regs->eflags = ctx.context.uc_mcontext.gregs[REG_EFL];
    regs->esp = ctx.context.uc_mcontext.gregs[REG_UESP];
    regs->ss = ctx.context.uc_mcontext.gregs[REG_SS];
    regs->vector = 0;

    asm("frstor %0" ::"m"(ctx.fpu));

    if (ctx.on_sigstack) {
        current->sigstack.ss_flags &= ~SS_ONSTACK;
    }

    sanitize_seg(&regs->gs, false, GDT_SEL_TDATA);
    sanitize_seg(&regs->fs, false, GDT_SEL_UDATA);
    sanitize_seg(&regs->es, false, GDT_SEL_UDATA);
    sanitize_seg(&regs->ds, false, GDT_SEL_UDATA);
    sanitize_seg(&regs->cs, true, GDT_SEL_UCODE);
    sanitize_seg(&regs->ss, false, GDT_SEL_UDATA);

    regs->eflags = sanitize_eflags(regs->eflags);

    return 0;
}

void sigset_sanitize(sigset_t *set) {
    sigset_clear(set, 0);
    sigset_clear(set, SIGKILL);
    sigset_clear(set, SIGSTOP);

    set->sig[(NSIG - 1) / 32] &= ~(0xfffffffful << ((NSIG - 1) % 32 + 1));

    for (unsigned i = (NSIG - 1) / 32 + 1; i < sizeof(set->sig) / sizeof(*set->sig); i++) {
        set->sig[i] = 0;
    }
}

void sigset_clear(sigset_t *set, unsigned sig) {
    ASSERT(sig < NSIG);
    set->sig[sig / 32] &= ~(1ul << (sig % 32));
}

void sigset_set(sigset_t *set, unsigned sig) {
    ASSERT(sig < NSIG);
    set->sig[sig / 32] |= (1ul << (sig % 32));
}

void sigset_join(sigset_t *set, const sigset_t *extra) {
    for (size_t i = 0; i < sizeof(set->sig) / sizeof(*set->sig); i++) {
        set->sig[i] |= extra->sig[i];
    }
}

void sigset_cmask(sigset_t *set, const sigset_t *mask) {
    for (size_t i = 0; i < sizeof(set->sig) / sizeof(*set->sig); i++) {
        set->sig[i] &= ~mask->sig[i];
    }

    sigset_clear(set, 0);
    sigset_clear(set, SIGKILL);
    sigset_clear(set, SIGSTOP);
}

bool sigset_get(sigset_t *set, unsigned sig) {
    ASSERT(sig < NSIG);
    return set->sig[sig / 32] & (1ul << (sig % 32));
}
