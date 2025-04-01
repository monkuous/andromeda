#include "signal.h"
#include "compiler.h"
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

void send_signal(process_t *process, thread_t *thread, siginfo_t *info) {
    ASSERT(info->si_code < NSIG);

    signal_target_t *target = thread ? &thread->signals : &process->signals;
    pending_signal_t *buf = target->signals[info->si_code];

    if (!buf) {
        buf = vmalloc(sizeof(*buf));
        target->signals[info->si_code] = buf;
        target->num_pending += 1;
    }

    memcpy(&buf->info, info, sizeof(*buf));
    buf->src = current->process->ruid;

    if (info->si_code == SIGCONT) proc_continue(process, buf);

    if (!process->nrunning) {
        if (info->si_code == SIGKILL) proc_continue(process, nullptr);
        else if (process->stopped) return;

        list_foreach(process->threads, thread_t, pnode, cur) {
            if (cur->state == THREAD_INTERRUPTIBLE) {
                sched_interrupt(cur);
                break;
            }
        }
    }
}

static bool is_masked(unsigned i) {
    ASSERT(i < NSIG);

    return current->signal_mask.sig[i / 32] & (1u << (i % 32));
}

static void join_masks(sigset_t *a, const sigset_t *b) {
    for (size_t i = 0; i < sizeof(a->sig) / sizeof(*a->sig); i++) {
        a->sig[i] |= b->sig[i];
    }
}

static void set_mask(sigset_t *mask, unsigned i) {
    mask->sig[i / 32] |= 1u << (i % 32);
}

typedef struct {
    uintptr_t ra;
    uintptr_t a2;
    uintptr_t a1;
    uintptr_t a0;
    siginfo_t info;
    ucontext_t context;
    bool on_sigstack : 1;
} sigctx_t;

static bool try_trigger_signals(signal_target_t *target) {
    if (!target->num_pending) return false;
    bool force_default = false;

retry:
    pending_signal_t *sig;
    int i;

    for (i = 0; i < NSIG; i++) {
        if (is_masked(i)) continue;
        sig = target->signals[i];
        if (sig) break;
    }

    if (!sig) return false;

    ASSERT(sig->info.si_code == i);

    struct sigaction *action = &current->process->signal_handlers[i];

    if (!force_default && action->sa_handler != SIG_DFL) {
        idt_frame_t *regs = &current->regs;

        if ((action->sa_flags & SA_RESTART) && regs->vector == 0x20) {
            regs->vector = 0;
            regs->eip -= 2;
        }

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
        ctx.a0 = i;
        ctx.a1 = ctx_addr + offsetof(sigctx_t, info);
        ctx.a2 = ctx_addr + offsetof(sigctx_t, context);
        ctx.on_sigstack = on_sigstack;

        ctx.context.uc_sigmask = current->signal_mask;
        ctx.context.uc_mcontext.gregs[REG_GS] = regs->gs;
        ctx.context.uc_mcontext.gregs[REG_FS] = regs->fs;
        ctx.context.uc_mcontext.gregs[REG_ES] = regs->es;
        ctx.context.uc_mcontext.gregs[REG_DS] = regs->ds;
        ctx.context.uc_mcontext.gregs[REG_EDI] = regs->edi;
        ctx.context.uc_mcontext.gregs[REG_ESI] = regs->esi;
        ctx.context.uc_mcontext.gregs[REG_EBP] = regs->ebp;
        ctx.context.uc_mcontext.gregs[REG_ESP] = regs->esp;
        ctx.context.uc_mcontext.gregs[REG_EBX] = regs->ebx;
        ctx.context.uc_mcontext.gregs[REG_EDX] = regs->edx;
        ctx.context.uc_mcontext.gregs[REG_ECX] = regs->ecx;
        ctx.context.uc_mcontext.gregs[REG_EAX] = regs->eax;
        ctx.context.uc_mcontext.gregs[REG_EIP] = regs->eip;
        ctx.context.uc_mcontext.gregs[REG_CS] = regs->cs;
        ctx.context.uc_mcontext.gregs[REG_EFL] = regs->eflags;
        ctx.context.uc_mcontext.gregs[REG_UESP] = regs->esp;
        ctx.context.uc_mcontext.gregs[REG_SS] = regs->ss;

        memcpy(&ctx.info, &sig->info, sizeof(sig->info));

        if (unlikely(user_memcpy((void *)ctx_addr, &ctx, sizeof(ctx)))) {
            if (i == SIGSEGV) force_default = true;
            goto retry;
        }

        join_masks(&current->signal_mask, &action->sa_mask);
        if (!(action->sa_flags & SA_NODEFER)) set_mask(&current->signal_mask, i);

        regs->eip = (uintptr_t)action->sa_handler;
        regs->esp = ctx_addr;

        if (i != SIGILL && i != SIGTRAP && (action->sa_flags & SA_RESETHAND)) {
            action->sa_handler = nullptr;
            action->sa_flags &= ~SA_SIGINFO;
        }
    } else if (force_default || action->sa_handler != SIG_IGN) {
        signal_disp_t disp = get_default_disposition(i);

        switch (disp) {
        case SD_TERMINATE: proc_kill(sig); break;
        case SD_IGNORE: break;
        case SD_STOP: proc_stop(sig); break;
        }
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

int return_from_signal() {
    idt_frame_t *regs = &current->regs;

    sigctx_t ctx;
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

    if (ctx.on_sigstack) {
        current->sigstack.ss_flags &= ~SS_ONSTACK;
    }

    return 0;
}
