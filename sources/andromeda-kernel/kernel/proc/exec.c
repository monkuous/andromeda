#include "exec.h"
#include "compiler.h"
#include "cpu/gdt.h"
#include "cpu/idt.h"
#include "fs/vfs.h"
#include "mem/pmap.h"
#include "mem/usermem.h"
#include "mem/vmalloc.h"
#include "mem/vmm.h"
#include "proc/process.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "util/panic.h"
#include <andromeda/string.h>
#include <elf.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#define USER_STACK_SIZE 0x800000

static const unsigned char wanted_ident[] = {ELFMAG0, ELFMAG1, ELFMAG2, ELFMAG3, ELFCLASS32, ELFDATA2LSB, EV_CURRENT};

struct elf_data {
    uintptr_t slide;
    uintptr_t entrypoint;
    struct {
        uintptr_t base;
        size_t count;
        size_t entry_size;
    } phdr;
    struct {
        void *data;
        size_t len;
    } interp;
};

struct eproc_data {
    uid_t euid;
    gid_t egid;
};

static int load_elf(file_t *file, struct elf_data *out, bool require_dyn) {
    int error;

    Elf32_Ehdr header;
    ssize_t count = vfs_pread(file, &header, sizeof(header), 0);
    if (unlikely(count < 0)) return -count;
    if (unlikely((size_t)count < sizeof(header))) return ENOEXEC;

    if (unlikely(memcmp(header.e_ident, wanted_ident, sizeof(wanted_ident)))) return ENOEXEC;
    if (unlikely(header.e_version != EV_CURRENT)) return ENOEXEC;
    if (unlikely(require_dyn && header.e_type == ET_EXEC)) return ENOEXEC;
    if (unlikely(header.e_type != ET_EXEC && header.e_type != ET_DYN)) return ENOEXEC;
    if (unlikely(header.e_machine != EM_386)) return ENOEXEC;

    ssize_t phdrsz = (ssize_t)header.e_phnum * header.e_phentsize;
    void *phdrs = vmalloc(phdrsz);
    count = vfs_pread(file, phdrs, phdrsz, header.e_phoff);
    if (unlikely(count < 0)) return -count;
    if (unlikely(count < phdrsz)) goto einval;

    uintptr_t head = UINTPTR_MAX;
    uintptr_t tail = 0;
    Elf32_Phdr *interp = nullptr;
    Elf32_Phdr *phdr = nullptr;

    for (size_t i = 0; i < header.e_phnum; i++) {
        Elf32_Phdr *cur = phdrs + i * header.e_phentsize;

        switch (cur->p_type) {
        case PT_LOAD: {
            if (!cur->p_memsz) break;
            if (cur->p_filesz > cur->p_memsz) goto einval;
            if (cur->p_filesz && (cur->p_offset & PAGE_MASK) != (cur->p_vaddr & PAGE_MASK)) goto einval;

            uintptr_t chead = cur->p_vaddr;
            uintptr_t ctail = chead + (cur->p_memsz - 1);
            if (ctail < chead) goto einval;

            if (chead < head) head = chead;
            if (ctail > tail) tail = ctail;
            break;
        }
        case PT_INTERP:
            if (interp) goto einval;
            if (cur->p_filesz > cur->p_memsz) goto einval;
            interp = cur;
            break;
        case PT_PHDR:
            if (phdr) goto einval;
            phdr = cur;
            break;
        }
    }

    if (head > tail) goto einval;

    if (interp) {
        if (!phdr) goto einval;

        out->interp.len = interp->p_memsz;
        out->interp.data = vmalloc(out->interp.len);
        count = vfs_pread(file, out->interp.data, interp->p_filesz, interp->p_offset);
        if (unlikely(count < 0)) {
            error = -count;
            vmfree(out->interp.data, out->interp.len);
            goto error;
        }

        if (unlikely((size_t)count < interp->p_filesz)) {
            vmfree(out->interp.data, out->interp.len);
            goto einval;
        }

        if (interp->p_filesz < out->interp.len) {
            memset(out->interp.data + interp->p_filesz, 0, out->interp.len - interp->p_filesz);
        }

        out->phdr.base = phdr->p_vaddr;
        out->phdr.count = header.e_phnum;
        out->phdr.entry_size = header.e_phentsize;
    }

    head &= ~PAGE_MASK;
    tail |= PAGE_MASK;

    uintptr_t addr = head;
    size_t area_size = tail - head + 1;
    error = vm_map(
            &addr,
            area_size,
            MAP_ANON | MAP_PRIVATE | (header.e_type == ET_EXEC ? MAP_FIXED : 0),
            PROT_NONE,
            nullptr,
            0
    );
    if (unlikely(error)) goto error;

    uintptr_t slide = addr - head;
    out->slide = slide;
    out->entrypoint = header.e_entry + slide;

    for (size_t i = 0; i < header.e_phnum; i++) {
        Elf32_Phdr *phdr = phdrs + i * header.e_phentsize;
        if (phdr->p_type != PT_LOAD) continue;

        size_t pgoff = phdr->p_vaddr & PAGE_MASK;

        uintptr_t map_addr = phdr->p_vaddr + slide - pgoff;
        size_t map_size = (phdr->p_memsz + pgoff + PAGE_MASK) & ~PAGE_MASK;
        int prot = 0;

        if (phdr->p_flags & PF_R) prot |= PROT_READ;
        if (phdr->p_flags & PF_W) prot |= PROT_WRITE;
        if (phdr->p_flags & PF_X) prot |= PROT_EXEC;

        if (phdr->p_filesz) {
            size_t data_size = phdr->p_filesz + pgoff;
            size_t fmap_size = (data_size + PAGE_MASK) & ~PAGE_MASK;
            bool need_write = data_size != fmap_size;

            error = vm_map(
                    &map_addr,
                    fmap_size,
                    MAP_PRIVATE | MAP_FIXED,
                    prot | (need_write ? PROT_WRITE : 0),
                    file,
                    phdr->p_offset - pgoff
            );
            if (unlikely(error)) goto error;

            if (need_write) {
                error = user_memset((void *)(map_addr + data_size), 0, fmap_size - data_size);
                if (unlikely(error)) goto error;

                if (!(prot & PROT_WRITE)) {
                    error = vm_remap(map_addr, fmap_size, prot);
                    if (unlikely(error)) goto error;
                }
            }

            map_addr += fmap_size;
            map_size -= fmap_size;
        }

        if (map_size) {
            error = vm_map(&map_addr, map_size, MAP_ANON | MAP_PRIVATE | MAP_FIXED, prot, nullptr, 0);
            if (unlikely(error)) goto error;
        }
    }

    vmfree(phdrs, phdrsz);
    return 0;

einval:
    error = EINVAL;
error:
    vmfree(out->interp.data, out->interp.len);
    vmfree(phdrs, phdrsz);
    return error;
}

struct vm_data {
    uintptr_t entrypoint;
    uintptr_t stack;
};

struct stackarea {
    void *base;
    size_t size;
    size_t total;
};

struct stackctx {
    struct stackarea base;
    struct stackarea info;
};

static void sa_write(struct stackarea *area, const void *src, size_t size, void **out) {
    if (out) *out = area->base;

    if (size <= area->size) {
        [[maybe_unused]] int error = user_memcpy(area->base, src, size);
        ASSERT(!error); // the memory area is allocated by us, so user_memcpy failing is a bug

        area->base += size;
        area->size -= size;
    }

    area->total += size;
}

static int sa_copy(struct stackarea *area, vm_t *srcvm, const void *src, size_t isize, size_t osize, void **out) {
    if (out) *out = area->base;

    if (osize <= area->size) {
        int error = vm_copy(area->base, srcvm, src, isize);
        if (unlikely(error)) return error;

        area->base += osize;
        area->size -= osize;
    }

    area->total += osize;
    return 0;
}

static int copy_strings(struct stackctx *ctx, vm_t *srcvm, const andromeda_tagged_string_t *strs, size_t count) {
    while (count--) {
        andromeda_tagged_string_t str;
        int error = user_memcpy(&str, strs++, sizeof(str));
        if (unlikely(error)) return error;

        void *ptr;
        error = sa_copy(&ctx->info, srcvm, str.data, str.length, str.length + 1, &ptr);
        if (unlikely(error)) return error;
        sa_write(&ctx->base, &ptr, sizeof(ptr), nullptr);
    }

    void *ptr = nullptr;
    sa_write(&ctx->base, &ptr, sizeof(ptr), nullptr);

    return 0;
}

static void write_auxv(struct stackarea *area, int tag, uintptr_t value) {
    Elf32_auxv_t auxv = {tag, {value}};
    sa_write(area, &auxv, sizeof(auxv), nullptr);
}

static int write_stack(
        struct stackctx *ctx,
        vm_t *old_vm,
        const andromeda_tagged_string_t *argv,
        size_t nargv,
        const andromeda_tagged_string_t *envp,
        size_t nenvp,
        struct eproc_data *eproc,
        struct elf_data *exec,
        struct elf_data *interp
) {
    sa_write(&ctx->base, &nargv, sizeof(nargv), nullptr);

    int error = copy_strings(ctx, old_vm, argv, nargv);
    if (unlikely(error)) return error;

    error = copy_strings(ctx, old_vm, envp, nenvp);
    if (unlikely(error)) return error;

    if (interp) {
        write_auxv(&ctx->base, AT_BASE, interp->slide);
        write_auxv(&ctx->base, AT_ENTRY, exec->entrypoint);
        write_auxv(&ctx->base, AT_PHDR, exec->phdr.base);
        write_auxv(&ctx->base, AT_PHENT, exec->phdr.entry_size);
        write_auxv(&ctx->base, AT_PHNUM, exec->phdr.count);
    }

    write_auxv(&ctx->base, AT_PAGESZ, PAGE_SIZE);
    write_auxv(&ctx->base, AT_UID, current->process->ruid);
    write_auxv(&ctx->base, AT_EUID, eproc->euid);
    write_auxv(&ctx->base, AT_GID, current->process->rgid);
    write_auxv(&ctx->base, AT_EGID, current->process->egid);
    write_auxv(&ctx->base, AT_NULL, 0);
    return 0;
}

static int create_stack(
        vm_t *old_vm,
        const andromeda_tagged_string_t *argv,
        size_t nargv,
        const andromeda_tagged_string_t *envp,
        size_t nenvp,
        struct eproc_data *eproc,
        struct elf_data *exec,
        struct elf_data *interp,
        struct vm_data *out
) {
    struct stackctx ctx = {};
    int error = write_stack(&ctx, old_vm, argv, nargv, envp, nenvp, eproc, exec, interp);
    if (unlikely(error)) return error;

    size_t base_size = ctx.base.total;
    size_t info_size = ctx.info.total;

    uintptr_t stack_base = 0;
    size_t stack_size = USER_STACK_SIZE + ((base_size + info_size + PAGE_MASK) & ~PAGE_MASK);
    error = vm_map(&stack_base, stack_size + PAGE_SIZE, MAP_ANON | MAP_PRIVATE, PROT_NONE, nullptr, 0);
    if (unlikely(error)) return error;

    stack_base += PAGE_SIZE; /* guard page */
    error = vm_map(&stack_base, stack_size, MAP_ANON | MAP_PRIVATE | MAP_FIXED, PROT_READ | PROT_WRITE, nullptr, 0);
    if (unlikely(error)) return error;

    ctx.base.base = (void *)(stack_base + USER_STACK_SIZE);
    ctx.base.size = base_size;
    ctx.base.total = 0;

    ctx.info.base = ctx.base.base + base_size;
    ctx.info.size = info_size;
    ctx.info.total = 0;

    error = write_stack(&ctx, old_vm, argv, nargv, envp, nenvp, eproc, exec, interp);
    if (unlikely(error)) return error;

    ASSERT(ctx.base.total == base_size);
    ASSERT(ctx.info.total == info_size);

    out->stack = stack_base + USER_STACK_SIZE;
    return 0;
}

static int do_create_vm(
        file_t *file,
        vm_t *old_vm,
        const andromeda_tagged_string_t *argv,
        size_t nargv,
        const andromeda_tagged_string_t *envp,
        size_t nenvp,
        struct eproc_data *eproc,
        struct vm_data *out
) {
    struct elf_data exec_data = {}, interp_buf = {};
    int error = load_elf(file, &exec_data, false);
    if (unlikely(error)) return error;

    struct elf_data *interp_data;

    if (exec_data.interp.len) {
        file_t *interp;
        error = vfs_open(
                &interp,
                nullptr,
                exec_data.interp.data,
                strnlen(exec_data.interp.data, exec_data.interp.len),
                O_RDONLY,
                0
        );
        vmfree(exec_data.interp.data, exec_data.interp.len);
        if (unlikely(error)) return error;

        error = load_elf(interp, &interp_buf, true);
        file_deref(interp);
        if (unlikely(error)) return error;

        if (interp_buf.interp.len) {
            vmfree(interp_buf.interp.data, interp_buf.interp.len);
            return ENOEXEC;
        }

        interp_data = &interp_buf;
    } else {
        interp_data = nullptr;
    }

    error = create_stack(old_vm, argv, nargv, envp, nenvp, eproc, &exec_data, interp_data, out);
    if (unlikely(error)) return error;

    out->entrypoint = interp_data ? interp_data->entrypoint : exec_data.entrypoint;
    return 0;
}

static int create_vm(
        file_t *file,
        const andromeda_tagged_string_t *argv,
        size_t nargv,
        const andromeda_tagged_string_t *envp,
        size_t nenvp,
        struct eproc_data *eproc,
        struct vm_data *out
) {
    vm_t *vm = vm_create();
    vm_t *old = vm_join(vm);

    int error = do_create_vm(file, old, argv, nargv, envp, nenvp, eproc, out);
    if (unlikely(error)) {
        clean_cur_pmap();
        vm_join(old);
        vm_free(vm);
        return error;
    }

    if (likely(old) && --old->references == 0) {
        vm_join(old);
        clean_cur_pmap();
        vm_join(vm);
        vm_free(old);
    }

    return 0;
}

static void build_eproc_data(file_t *file, struct eproc_data *out) {
    out->euid = current->process->euid;
    out->egid = current->process->egid;

    if (!(file->inode->filesystem->flags & ST_NOSUID)) {
        if (file->inode->mode & S_ISUID) out->euid = file->inode->uid;
        if (file->inode->mode & S_ISGID) out->egid = file->inode->gid;
    }
}

static void alter_process(struct eproc_data *data) {
    kill_other_threads();

    for (int i = 0; i < NSIG; i++) {
        struct sigaction *action = &current->process->signal_handlers[i];

        if (i == SIGCHLD || action->sa_handler != SIG_IGN) action->sa_handler = SIG_DFL;

        action->sa_flags = 0;
        action->sa_restorer = nullptr;
        action->sa_mask = (sigset_t){};
    }

    for (size_t i = 0; i < current->process->fds_cap; i++) {
        struct fd *fd = &current->process->fds[i];

        if (fd->flags & FD_CLOEXEC) {
            file_deref(fd->file);
            fd->file = nullptr;
            fd->flags = 0;

            if (i < current->process->fds_start) {
                current->process->fds_start = i;
            }
        }
    }

    current->process->euid = data->euid;
    current->process->egid = data->egid;
    current->process->suid = current->process->euid;
    current->process->sgid = current->process->egid;
    current->process->did_exec = true;
}

static void setup_regs(idt_frame_t *frame, struct vm_data *vm_data) {
    memset(frame, 0, sizeof(*frame));
    frame->eip = vm_data->entrypoint;
    frame->esp = vm_data->stack;
    frame->cs = GDT_SEL_UCODE;
    frame->ds = GDT_SEL_UDATA;
    frame->es = GDT_SEL_UDATA;
    frame->fs = GDT_SEL_UDATA;
    frame->gs = GDT_SEL_TDATA;
    frame->ss = GDT_SEL_UDATA;
}

int execute(
        file_t *file,
        const andromeda_tagged_string_t *argv,
        size_t nargv,
        const andromeda_tagged_string_t *envp,
        size_t nenvp
) {
    if (unlikely(!S_ISREG(file->inode->mode))) return EACCES;

    int error = access_inode(file->inode, X_OK, false);
    if (unlikely(error)) return error;

    struct eproc_data eproc_data;
    build_eproc_data(file, &eproc_data);

    struct vm_data vm_data;
    error = create_vm(file, argv, nargv, envp, nenvp, &eproc_data, &vm_data);
    if (unlikely(error)) return error;

    alter_process(&eproc_data);
    setup_regs(&current->regs, &vm_data);

    return 0;
}
