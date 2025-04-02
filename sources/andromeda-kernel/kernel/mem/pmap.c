#include "pmap.h"
#include "asm/cr.h"
#include "compiler.h"
#include "cpu/idt.h"
#include "fs/pgcache.h"
#include "mem/layout.h"
#include "mem/pmem.h"
#include "mem/vmm.h"
#include "proc/sched.h"
#include "proc/signal.h"
#include "string.h"
#include "util/panic.h"
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <sys/mman.h>

#define PTE_PRESENT (1u << 0)
#define PTE_WRITABLE PMAP_WRITABLE
#define PTE_USER (1u << 2)
#define PTE_ACCESSED (1u << 5)
#define PTE_DIRTY (1u << 6)
#define PTE_ANON (1u << 9) /* this is an anonymous page */
#define PTE_COW (1u << 10) /* this is a copy-on-write page that hasn't been written to yet */
#define PTE_ADDR 0xfffff000

#define PF_ERR_WRITE 2

#define TABLE_FLAGS (PTE_ACCESSED | PTE_USER | PTE_WRITABLE | PTE_PRESENT)

#define CUR_PAGE_DIR ((uint32_t *)(PTBL_VIRT_BASE | (PTBL_VIRT_BASE >> 10)))

extern uint32_t kernel_page_dir[1024];
static uint32_t kernel_pd_phys;

static uint32_t *temp_map_pte;
alignas(PAGE_SIZE) static char temp_map_page[PAGE_SIZE];

static inline void invlpg(uintptr_t addr) {
    asm("invlpg (%0)" ::"r"(addr) : "memory");
}

void init_pmap() {
    kernel_pd_phys = (uintptr_t)kernel_page_dir - KERN_VIRT_BASE;
    temp_map_pte = (uint32_t *)(PTBL_VIRT_BASE | ((uintptr_t)temp_map_page >> 10));
    *temp_map_pte = 0;
    invlpg((uintptr_t)temp_map_page);
    pmem_free(phys_to_page((uintptr_t)temp_map_page - KERN_VIRT_BASE), false);
}

void create_pmap(pmap_t *pmap) {
    pmap->page_dir_phys = page_to_phys(pmem_alloc(false));
    uint32_t *map = pmap_tmpmap(pmap->page_dir_phys);
    memset(map, 0, PAGE_SIZE / 2);
    memcpy(&map[512], &kernel_page_dir[512], PAGE_SIZE / 2);
    map[(PTBL_VIRT_BASE >> 22) & 1023] = pmap->page_dir_phys | (TABLE_FLAGS & ~PTE_USER);
}

void free_pmap(pmap_t *pmap) {
    pmem_free(phys_to_page(pmap->page_dir_phys), false);
}

static void handle_unmap(uint32_t pte) {
    if (pte & PTE_ANON) {
        page_t *page = phys_to_page(pte & PTE_ADDR);

        if (--page->anon.references == 0) {
            pmem_free(page, false);
        }
    }
}

void clean_cur_pmap() {
    uint32_t *pd = CUR_PAGE_DIR;
    uint32_t *kpd = &pd[512];
    uint32_t *pt = (uint32_t *)PTBL_VIRT_BASE;

    while (pd < kpd) {
        uint32_t pde = *pd++;

        if (pde) {
            do {
                uint32_t pte = *pt++;
                if (pte) handle_unmap(pte);
            } while ((uintptr_t)pt & PAGE_MASK);

            pmem_free(phys_to_page(pde & PTE_ADDR), false);
        } else {
            pt += 1024;
        }
    }
}

void switch_pmap(pmap_t *target) {
    write_cr3(likely(target) ? target->page_dir_phys : kernel_pd_phys);
}

static bool is_usermem(uintptr_t eip) {
    extern const void __usermem_start, __usermem_end;
    return eip >= (uintptr_t)&__usermem_start && eip < (uintptr_t)&__usermem_end;
}

static void usermem_ret(idt_frame_t *frame, int error) {
    frame->eax = error;
    frame->ecx = 0;
}

static void sendsig(int signo, int error, uintptr_t addr) {
    siginfo_t info = {.si_signo = signo, .si_errno = error, .si_addr = (void *)addr};
    send_signal(current->process, current, &info);
}

static bool anon_cow_preserve(uint32_t pte) {
    page_t *page = phys_to_page(pte & PTE_ADDR);
    if (page->anon.references == 1) return true;
    page->anon.references -= 1;
    return false;
}

static uint32_t do_cow(uint32_t pte, uintptr_t addr) {
    if (!(pte & PTE_ANON) || !anon_cow_preserve(pte)) {
        page_t *page = pmem_alloc(false);
        page->anon.references = 1;
        uint32_t phys = page_to_phys(page);

        // this check is necessary to prevent a 2nd page fault from occurring
        // if pmem_alloc evicted the page we're copying
        if (phys != (pte & PTE_ADDR)) {
            memcpy(pmap_tmpmap(phys), (const void *)(addr & ~PAGE_MASK), PAGE_SIZE);
        }

        pte = (pte & ~PTE_ADDR) | phys | PTE_ANON;
    }

    return pte | PTE_WRITABLE;
}

static void create_mapping(idt_frame_t *frame, vm_region_t *region, uintptr_t addr, uint32_t *ptep, bool write) {
    uint32_t pte = PTE_DIRTY | PTE_ACCESSED | PTE_USER | PTE_PRESENT;

    if (region->src.inode) {
        uint64_t offset = region->offset + (addr - region->head);

        page_t *page;
        int error = pgcache_get_page(&region->src.inode->data, &page, offset >> PAGE_SHIFT, true);
        if (unlikely(error)) {
            sendsig(SIGBUS, error, addr);
            if (!(frame->cs & 3)) usermem_ret(frame, EINTR);
            return;
        }

        pte |= page_to_phys(page);

        if (region->flags & MAP_PRIVATE) {
            if (write) {
                *ptep = pte;
                pte = do_cow(pte, addr);
                *ptep = pte;
                invlpg(addr);
                return;
            } else {
                pte |= PTE_COW;
            }
        } else if (region->prot & PROT_WRITE) {
            pte |= PTE_WRITABLE;
        }

        *ptep = pte;
    } else {
        page_t *page = pmem_alloc(false);
        page->anon.references = 1;
        pte |= page_to_phys(page);
        if (region->prot & PROT_WRITE) pte |= PTE_WRITABLE;

        *ptep = pte;
        memset((void *)(addr & ~PAGE_MASK), 0, PAGE_SIZE);
    }
}

static void ensure_pt_present(uint32_t *pd, uint32_t pdi) {
    if (!pd[pdi]) {
        pd[pdi] = pmem_alloc_simple() | TABLE_FLAGS;
        memset((uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)), 0, 0x1000);
    }
}

static bool fix_user_fault(idt_frame_t *frame, uintptr_t addr) {
    vm_region_t *region = vm_get_region(addr);
    if (unlikely(!region)) return false;
    if (unlikely(!region->prot)) return false;

    bool write = frame->error & PF_ERR_WRITE;
    if (unlikely(write && !(region->prot & PROT_WRITE))) return false;

    ensure_pt_present(CUR_PAGE_DIR, (addr >> 22) & 1023);
    uint32_t *ptep = (uint32_t *)(PTBL_VIRT_BASE | ((addr >> 10) & ~3));
    uint32_t pte = *ptep;

    uint32_t tmpmap = *temp_map_pte;

    if (write && (pte & PTE_COW)) {
        *ptep = do_cow(pte, addr);
        invlpg(addr);
    } else {
        ASSERT(!pte);
        create_mapping(frame, region, addr, ptep, write);
    }

    if (tmpmap != *temp_map_pte) {
        *temp_map_pte = tmpmap;
        invlpg((uintptr_t)temp_map_page);
    }

    return true;
}

static void handle_user_fault(idt_frame_t *frame, uintptr_t addr) {
    if (unlikely(!(frame->cs & 3) && !is_usermem(frame->eip))) {
        handle_fatal_exception(frame);
    }

    if (likely(fix_user_fault(frame, addr))) return;

    sendsig(SIGSEGV, EFAULT, addr);
    if (!(frame->cs & 3)) usermem_ret(frame, EFAULT);
}

static void handle_kern_fault(idt_frame_t *frame, uintptr_t addr) {
    if (unlikely(frame->cs & 3)) {
        sendsig(SIGSEGV, EFAULT, addr);
        return;
    }

    size_t pdi = (addr >> 22) & 1023;
    if (likely(CUR_PAGE_DIR[pdi] != kernel_page_dir[pdi])) {
        CUR_PAGE_DIR[pdi] = kernel_page_dir[pdi];
        return;
    }

    handle_fatal_exception(frame);
}

void handle_page_fault(idt_frame_t *frame) {
    uintptr_t addr = read_cr2();

    if (likely(addr < KERN_VIRT_BASE)) {
        handle_user_fault(frame, addr);
    } else {
        handle_kern_fault(frame, addr);
    }
}

void pmap_map(uintptr_t virt, uint32_t phys, size_t size, uint32_t flags) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(size);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT((virt < KERN_VIRT_BASE) == (tail < KERN_VIRT_BASE));
    ASSERT(tail < PTBL_VIRT_BASE);

    flags |= PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;
    if (virt < KERN_VIRT_BASE) flags |= PTE_USER;

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *pdir = virt < KERN_VIRT_BASE ? CUR_PAGE_DIR : kernel_page_dir;
    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;
        ensure_pt_present(pdir, pdi);

        while (pti <= pti_end) {
            ASSERT(*table == 0);
            *table++ = phys | flags;
            pti++;
            phys += 0x1000;
        }

        pdi++;
        pti = 0;
    }
}

void pmap_alloc(uintptr_t virt, size_t size, uint32_t flags, bool anon) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(size);
    ASSERT(virt >= KERN_VIRT_BASE);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT(tail < PTBL_VIRT_BASE);

    flags |= PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;
        ensure_pt_present(kernel_page_dir, pdi);

        while (pti <= pti_end) {
            ASSERT(*table == 0);

            uint32_t phys;

            if (anon) {
                page_t *page = pmem_alloc(false);
                page->anon.references = 1;
                phys = page_to_phys(page) | PTE_ANON;
            } else {
                phys = pmem_alloc_simple();
            }

            *table++ = phys | flags;
            pti++;
        }

        pdi++;
        pti = 0;
    }
}

void pmap_clone(pmap_t *out, uintptr_t virt, size_t size, bool cow) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(size);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT(tail < KERN_VIRT_BASE);

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;

        if (CUR_PAGE_DIR[pdi]) {
            uint32_t *odir = pmap_tmpmap(out->page_dir_phys);
            uint32_t ophys = odir[pdi];
            uint32_t *otbl;

            if (ophys) {
                ophys &= PTE_ADDR;
                otbl = pmap_tmpmap(ophys);
            } else {
                ophys = pmem_alloc_simple();
                odir[pdi] = ophys | TABLE_FLAGS;
                otbl = pmap_tmpmap(ophys);
                memset(otbl, 0, PAGE_SIZE);
            }

            otbl += pti;

            while (pti <= pti_end) {
                uint32_t pte = *table;

                if (cow) {
                    pte |= PTE_COW;

                    if (pte & PTE_WRITABLE) {
                        pte &= ~PTE_WRITABLE;
                        *table = pte;
                        invlpg((uintptr_t)table << 10);
                    } else {
                        *table = pte;
                    }
                }

                if (pte & PTE_ANON) {
                    phys_to_page(pte)->anon.references += 1;
                }

                *otbl++ = pte;
                table++;
                pti++;
            }
        } else {
            table += pti_end - pti + 1;
        }

        pdi++;
        pti = 0;
    }
}

void pmap_remap(uintptr_t virt, size_t size, uint32_t flags) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(size);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT((virt < KERN_VIRT_BASE) == (tail < KERN_VIRT_BASE));
    ASSERT(tail < PTBL_VIRT_BASE);

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *directory = virt < KERN_VIRT_BASE ? CUR_PAGE_DIR : kernel_page_dir;
    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;

        if (directory[pdi]) {
            while (pti <= pti_end) {
                uint32_t pte = *table;

                if (pte) {
                    uint32_t npte = (pte & ~PTE_WRITABLE) | flags;

                    if (pte != npte) {
                        *table = npte;
                        invlpg((uintptr_t)table << 10);
                    }
                }

                table++;
                pti++;
            }
        } else {
            table += pti_end - pti + 1;
        }

        pdi++;
        pti = 0;
    }
}

void pmap_unmap(uintptr_t virt, size_t size) {
    ASSERT(!((virt | size) & PAGE_MASK));
    ASSERT(size);

    uintptr_t tail = virt + (size - 1);
    ASSERT(virt < tail);
    ASSERT((virt < KERN_VIRT_BASE) == (tail < KERN_VIRT_BASE));
    ASSERT(tail < PTBL_VIRT_BASE);

    uint32_t pdi = (virt >> 22) & 1023;
    uint32_t pti = (virt >> 12) & 1023;

    uint32_t pdi_end = (tail >> 22) & 1023;
    uint32_t pti_end = 1023;

    uint32_t *directory = virt < KERN_VIRT_BASE ? CUR_PAGE_DIR : kernel_page_dir;
    uint32_t *table = (uint32_t *)(PTBL_VIRT_BASE | (pdi << 12)) + pti;

    while (pdi <= pdi_end) {
        if (pdi == pdi_end) pti_end = (tail >> 12) & 1023;

        if (directory[pdi]) {
            while (pti <= pti_end) {
                uint32_t pte = *table;

                if (pte) {
                    *table = 0;
                    invlpg((uintptr_t)table << 10);
                    handle_unmap(pte);
                }

                table++;
                pti++;
            }
        } else {
            table += pti_end - pti + 1;
        }

        pdi++;
        pti = 0;
    }
}

void *pmap_tmpmap(uint32_t phys) {
    ASSERT(!(phys & PAGE_MASK));

    uint32_t pte = phys | PTE_DIRTY | PTE_ACCESSED | PTE_WRITABLE | PTE_PRESENT;

    if (pte != *temp_map_pte) {
        *temp_map_pte = pte;
        invlpg((uintptr_t)temp_map_page);
    }

    return temp_map_page;
}
