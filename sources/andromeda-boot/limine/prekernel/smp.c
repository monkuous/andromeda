#include "smp.h"
#include "acpi.h"
#include "asm.h"
#include "limine.h"
#include "memory.h"
#include "start.h"
#include "string.h"
#include <cpuid.h>
#include <stdatomic.h>
#include <stdint.h>

bool smp_using_x2apic;
static uint64_t apic_regs;

static struct {
    uint32_t cr3;
    uint32_t cr4;
    uint64_t efer;
    uint32_t jmp_target[2];
    uint16_t gdtr[3];
} *tdata;

static void setup_trampoline() {
    extern const void smp_trampoline_start, smp_trampoline_data, smp_trampoline_end;
    memcpy((void *)boot_info->mp_low_page, &smp_trampoline_start, &smp_trampoline_end - &smp_trampoline_start);
    tdata = (void *)boot_info->mp_low_page + (&smp_trampoline_data - &smp_trampoline_start);

    asm("mov %%cr3, %0" : "=r"(tdata->cr3));
    asm("mov %%cr4, %0" : "=r"(tdata->cr4));
    tdata->efer = rdmsr(0xc0000080);

    tdata->jmp_target[0] += (uintptr_t)&smp_trampoline_start;
    asm("sgdt %0" : "=m"(tdata->gdtr));
}

static bool setup_apic_regs(struct limine_mp_response *response) {
    unsigned eax, ebx, ecx, edx;
    if (!__get_cpuid(1, &eax, &ebx, &ecx, &edx)) return false;
    if (!(edx & (1u << 9))) return false; // APIC bit

    uint64_t msr = rdmsr(0x1b);

    if (ecx & (1u << 21)) {
        if (boot_info->mp_flags & LIMINE_MP_X2APIC) {
            if (!(msr & 0x400)) wrmsr(0x1b, msr | 0x400);
            response->flags |= LIMINE_MP_X2APIC;
            smp_using_x2apic = true;
            return true;
        } else if (msr & 0x400) {
            return false;
        }
    }

    apic_regs = msr & 0xffffffffff000;
    return true;
}

#define APIC_ID 0x20
#define APIC_ICR 0x300

static uint32_t apic_read(unsigned reg) {
    if (smp_using_x2apic) {
        return rdmsr(0x800 + (reg >> 4));
    } else {
        return mmio_read32(tmpmap(apic_regs + reg, false));
    }
}

static void apic_write64(unsigned reg, uint64_t value) {
    if (smp_using_x2apic) {
        wrmsr(0x800 + (reg >> 4), value);
    } else {
        void *ptr = tmpmap(apic_regs + reg, false);
        mmio_write32(ptr + 0x10, value >> 32);
        mmio_write32(ptr, value);
    }
}

uint32_t smp_current_id;
bool smp_ready;
uint32_t smp_stack;
uint64_t smp_info;

static bool start_cpu(struct limine_mp_info *info) {
    smp_current_id = info->lapic_id;
    smp_ready = false;
    smp_info = (uintptr_t)info + boot_info->responses.hhdm.offset;

    atomic_thread_fence(memory_order_seq_cst);

    uint64_t icr_dest_mask = (uint64_t)info->lapic_id << (smp_using_x2apic ? 32 : 56);

    apic_write64(APIC_ICR, icr_dest_mask | 0x4500); // INIT IPI
    tsc_delay(10000000);
    apic_write64(APIC_ICR, icr_dest_mask | 0x4600 | (boot_info->mp_low_page >> 12)); // Startup IPI

    for (int i = 0; i < 100; i++) {
        if (__atomic_load_n(&smp_current_id, __ATOMIC_SEQ_CST) == UINT32_MAX) goto wait_remaining;

        tsc_delay(10000000);
    }

    if (__atomic_exchange_n(&smp_current_id, UINT32_MAX, __ATOMIC_SEQ_CST) == UINT32_MAX) {
        goto wait_remaining;
    }

    return false;

wait_remaining:
    // the cpu is confirmed alive, we don't need a timeout anymore

    __atomic_store_n(
            &smp_stack,
            allocate_pages(boot_info->mp_stack_pages) + (1ul << boot_info->mp_stack_pages),
            __ATOMIC_SEQ_CST
    );

    while (!__atomic_load_n(&smp_ready, __ATOMIC_SEQ_CST)) {
        asm("");
    }

    return true;
}

void init_smp() {
    setup_trampoline();

    struct limine_mp_response *response = &boot_info->responses.mp;

    if (!setup_apic_regs(response)) return;

    response->bsp_lapic_id = apic_read(APIC_ID);
    if (!smp_using_x2apic) response->bsp_lapic_id >>= 24;

    uint64_t madt_addr;
    size_t madt_len = get_table(TABLE_MADT, &madt_addr);
    if (!madt_len) return;

    uint64_t madt_end = madt_addr + madt_len;
    madt_addr += sizeof(madt_t);

    size_t num_cpus = 0;

    for (uint64_t cur = madt_addr; cur < madt_end;) {
        madt_entry_t entry;
        copy_from_phys(&entry, cur, 2, true);

        if (entry.type == MADT_XAPIC) {
            copy_from_phys(&entry.xapic, cur + 2, sizeof(entry.xapic), true);
            if (!(entry.xapic.flags & (MADT_LAPIC_ONLINE_CAPABLE | MADT_LAPIC_ENABLED))) goto next;
            num_cpus += 1;
        } else if (entry.type == MADT_X2APIC) {
            copy_from_phys(&entry.x2apic, cur + 2, sizeof(entry.x2apic), true);
            if (!(entry.x2apic.flags & (MADT_LAPIC_ONLINE_CAPABLE | MADT_LAPIC_ENABLED))) goto next;
            num_cpus += 1;
        }

    next:
        cur += entry.length;
    }

    uint64_t *pointers = allocate(num_cpus * sizeof(*pointers));
    size_t idx = 0;

    response->cpus = (uintptr_t)pointers + boot_info->responses.hhdm.offset;

    for (uint64_t cur = madt_addr; cur < madt_end;) {
        madt_entry_t entry;
        copy_from_phys(&entry, cur, 2, true);

        uint32_t acpi_id;
        uint32_t apic_id;

        if (entry.type == MADT_XAPIC) {
            copy_from_phys(&entry.xapic, cur + 2, sizeof(entry.xapic), true);
            if (!(entry.xapic.flags & (MADT_LAPIC_ONLINE_CAPABLE | MADT_LAPIC_ENABLED))) goto next2;
            acpi_id = entry.xapic.acpi_id;
            apic_id = entry.xapic.apic_id;
        } else if (entry.type == MADT_X2APIC) {
            copy_from_phys(&entry.x2apic, cur + 2, sizeof(entry.x2apic), true);
            if (!(entry.x2apic.flags & (MADT_LAPIC_ONLINE_CAPABLE | MADT_LAPIC_ENABLED))) goto next2;
            acpi_id = entry.x2apic.acpi_id;
            apic_id = entry.x2apic.apic_id;
        } else {
            goto next2;
        }

        struct limine_mp_info *info = allocate(sizeof(*info));
        memset(info, 0, sizeof(*info));

        info->processor_id = acpi_id;
        info->lapic_id = apic_id;

        if (info->lapic_id == response->bsp_lapic_id || start_cpu(info)) {
            pointers[idx++] = (uintptr_t)info + boot_info->responses.hhdm.offset;
        }

    next2:
        cur += entry.length;
    }

    response->cpu_count = idx;

    uint64_t *ptr = tmpmap(boot_info->mp_response_field_ptr, true);
    *ptr = (uintptr_t)response + boot_info->responses.hhdm.offset;
}
