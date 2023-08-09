#include "machine.hpp"

#include <cassert>
#include <cstring>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "page_streaming.hpp"
#include "amd64/amd64.hpp"
#include "amd64/idt.hpp"
#include "amd64/gdt.hpp"
#include "amd64/lapic.hpp"
#include "amd64/tss.hpp"
#include "amd64/paging.hpp"
#include "amd64/memory_layout.hpp"
#include "amd64/usercode.hpp"
extern "C" int gettid();
extern "C" int close(int);
extern "C" void tinykvm_timer_signal_handler(int);
#define TINYKVM_USE_SYNCED_SREGS 1

struct ksigevent
{
	union sigval sigev_value;
	int sigev_signo;
	int sigev_notify;
	int sigev_tid;
};

namespace tinykvm {
	static struct kvm_xcrs master_xregs;
	static struct {
		__u32 nent;
		__u32 padding;
		struct kvm_cpuid_entry2 entries[100];
	} kvm_cpuid;
	static long vcpu_mmap_size = 0;

TINYKVM_COLD()
void initialize_vcpu_stuff(int kvm_fd)
{
	vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		throw MachineException("Failed to KVM_GET_VCPU_MMAP_SIZE");
	}

	/* Retrieve KVM-host CPUID features */
	kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);
	if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid) < 0) {
		throw MachineException("KVM_GET_SUPPORTED_CPUID failed");
	}
}

void* Machine::create_vcpu_timer()
{
	signal(SIGUSR2, tinykvm_timer_signal_handler);

	struct ksigevent sigev {};
	sigev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
	sigev.sigev_signo = SIGUSR2;
	sigev.sigev_tid = gettid();

	timer_t timer_id;
	if (timer_create(CLOCK_MONOTONIC, (struct sigevent *)&sigev, &timer_id) < 0)
		throw MachineException("Unable to create timeout timer");
	return timer_id;
}

void vCPU::init(int id, Machine& machine)
{
	this->cpu_id = id;
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->cpu_id);
	this->m_machine = &machine;
	if (UNLIKELY(this->fd < 0)) {
		Machine::machine_exception("Failed to KVM_CREATE_VCPU");
	}
	this->timer_id = Machine::create_vcpu_timer();

	kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(kvm_run == MAP_FAILED)) {
		Machine::machine_exception("Failed to create KVM run-time mapped memory");
	}
	/* We only want GPRs and SREGS for now. */
	kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS;
#ifdef TINYKVM_USE_SYNCED_SREGS
	kvm_run->kvm_valid_regs |= KVM_SYNC_X86_SREGS;
#endif

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		Machine::machine_exception("KVM_SET_CPUID2 failed");
	}

	// Only master VMs need special registers
	// Forked VMs derive special register from the master VM
	if (!this->machine().is_forked())
	{
		struct kvm_sregs master_sregs;
		if (ioctl(this->fd, KVM_GET_SREGS, &master_sregs) < 0) {
			Machine::machine_exception("KVM_GET_SREGS failed");
		}
		const auto physbase = machine.main_memory().physbase;

		master_sregs.cr3 = physbase + PT_ADDR;
		// NOTE: SMEP is not currently possible to due to the usermode
		// assembly being used in a kernel context. Some writing occurs?
		// XXX: TODO: Figure out why SMEP causes problems.
		master_sregs.cr4 =
			CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE |
			CR4_FSGSBASE;
		master_sregs.cr0 =
			CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
		master_sregs.efer =
			EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
		setup_amd64_segment_regs(master_sregs, physbase + GDT_ADDR);
		master_sregs.gs.base = usercode_header().translated_vm_cpuid(machine.main_memory());
		setup_amd64_tss_regs(master_sregs, physbase + TSS_ADDR);
		setup_amd64_exception_regs(master_sregs, physbase + IDT_ADDR);
		this->set_special_registers(master_sregs);
	}

	// Avoid loading X-regs more than once
	static bool minit = false;
	if (!minit) {
		minit = true;
		if (ioctl(this->fd, KVM_GET_XCRS, &master_xregs) < 0) {
			Machine::machine_exception("KVM_GET_XCRS failed");
		}
		/* Enable AVX and AVX512 instructions */
		master_xregs.xcrs[0].xcr = 0;
		master_xregs.xcrs[0].value |= 0x7; // FPU, SSE, YMM

		/* Host supports AVX-512F (most basic AVX-512 feature) */
		if (__builtin_cpu_supports("avx512f")) {
			master_xregs.xcrs[0].value |= 0xE0; // AVX512
		}
		master_xregs.nr_xcrs = 1;
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		Machine::machine_exception("KVM_SET_XCRS failed");
	}

	/* Enable SYSCALL/SYSRET instructions */
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad = 0;

		struct kvm_msr_entry entries[3];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_STAR;
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().translated_vm_syscall(machine.main_memory());

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < (int)msrs.nmsrs) {
		Machine::machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR");
	}
}

void vCPU::smp_init(int id, Machine& machine)
{
	this->cpu_id = id;
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->cpu_id);
	this->m_machine = &machine;
	auto& memory = machine.main_memory();

	if (UNLIKELY(this->fd < 0)) {
		Machine::machine_exception("Failed to KVM_CREATE_VCPU");
	}
	this->timer_id = Machine::create_vcpu_timer();

	kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(kvm_run == MAP_FAILED)) {
		Machine::machine_exception("Failed to create KVM run-time mapped memory");
	}
	/* We only want GPRs and SREGS for now. */
	kvm_run->kvm_valid_regs = KVM_SYNC_X86_REGS;
#ifdef TINYKVM_USE_SYNCED_SREGS
	kvm_run->kvm_valid_regs |= KVM_SYNC_X86_SREGS;
#endif

	const kvm_mp_state state {
		.mp_state = KVM_MP_STATE_RUNNABLE
	};
	if (ioctl(this->fd, KVM_SET_MP_STATE, &state) < 0) {
		Machine::machine_exception("KVM_SET_MP_STATE failed");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		Machine::machine_exception("KVM_SET_CPUID2 failed");
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		Machine::machine_exception("KVM_SET_XCRS failed");
	}

	/* Enable SYSCALL/SYSRET instructions */
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad = 0;

		struct kvm_msr_entry entries[2];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_STAR;
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().translated_vm_syscall(memory);

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < (int)msrs.nmsrs) {
		Machine::machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR");
	}

	auto& sregs = this->get_special_registers();
	/* XXX: Is this correct? */
	sregs = machine.vcpu.get_special_registers();
	sregs.tr.base = memory.physbase + TSS_SMP_ADDR + (id - 1) * 104; /* AMD64_TSS */
	sregs.gs.base = usercode_header().translated_vm_cpuid(memory) + 4 * id;
	/* XXX: Is this correct? */
	sregs.cr3 = memory.page_tables;
	sregs.cr0 &= ~CR0_WP; // XXX: Fix me!
	this->set_special_registers(sregs);
}

void vCPU::deinit()
{
	if (this->fd > 0) {
		close(this->fd);
	}
	if (kvm_run != nullptr) {
		munmap(kvm_run, vcpu_mmap_size);
	}

	timer_delete(this->timer_id);
}

const tinykvm_x86regs& vCPU::registers() const
{
	return *(tinykvm_x86regs *)&this->kvm_run->s.regs.regs;
}
tinykvm_x86regs& vCPU::registers()
{
	return *(tinykvm_x86regs *)&this->kvm_run->s.regs.regs;
}
void vCPU::set_registers(const struct tinykvm_x86regs& regs)
{
	this->kvm_run->kvm_dirty_regs |= KVM_SYNC_X86_REGS;
	auto* src_regs = (struct kvm_regs *) &regs;
	auto* dest_regs = &this->kvm_run->s.regs.regs;
	/* Only assign if there is a mismatch. */
	if (src_regs != dest_regs)
		*dest_regs = *src_regs;
}
tinykvm_fpuregs vCPU::fpu_registers() const
{
	struct tinykvm_fpuregs regs;
	if (ioctl(this->fd, KVM_GET_FPU, &regs) < 0) {
		Machine::machine_exception("KVM_GET_FPU failed");
	}
	return regs;
}
const kvm_sregs& vCPU::get_special_registers() const
{
#ifndef TINYKVM_USE_SYNCED_SREGS
	if (ioctl(this->fd, KVM_GET_SREGS, &this->kvm_run->s.regs.sregs) < 0) {
		Machine::machine_exception("KVM_GET_SREGS failed");
	}
#endif
	return this->kvm_run->s.regs.sregs;
}
kvm_sregs& vCPU::get_special_registers()
{
#ifndef TINYKVM_USE_SYNCED_SREGS
	if (ioctl(this->fd, KVM_GET_SREGS, &this->kvm_run->s.regs.sregs) < 0) {
		Machine::machine_exception("KVM_GET_SREGS failed");
	}
#endif
	return this->kvm_run->s.regs.sregs;
}
void vCPU::set_special_registers(const kvm_sregs& sregs)
{
#ifdef TINYKVM_USE_SYNCED_SREGS
	this->kvm_run->kvm_dirty_regs |= KVM_SYNC_X86_SREGS;

	auto* dest_regs = &this->kvm_run->s.regs.sregs;
	/* Only assign if there is a mismatch. */
	if (dest_regs != &sregs)
		*dest_regs = sregs;
#else
	if (ioctl(this->fd, KVM_SET_SREGS, &sregs) < 0) {
		Machine::machine_exception("KVM_SET_SREGS failed");
	}
#endif
}

std::string_view vCPU::io_data() const
{
	char *p = (char *) kvm_run;
	return {&p[kvm_run->io.data_offset], kvm_run->io.size};
}

void Machine::setup_long_mode(const Machine* other, const MachineOptions& options)
{
	(void)options;

	if (other == nullptr) // Main VM
	{
		const auto physbase = this->memory.physbase;

		setup_amd64_exceptions(
			physbase + INTR_ASM_ADDR,
			memory.at(physbase + IDT_ADDR), memory.at(physbase + INTR_ASM_ADDR));
		setup_amd64_segments(
			physbase + GDT_ADDR,
			memory.at(physbase + GDT_ADDR));
		setup_amd64_tss(memory);
		setup_amd64_tss_smp(memory);
		/* Userspace entry/exit code */
		setup_vm64_usercode(
			memory.at(physbase + USER_ASM_ADDR));

		this->m_kernel_end = setup_amd64_paging(memory, m_binary);
	}
	else // Forked VM
	{
		setup_cow_mode(other);
	}
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	const auto& sregs = vcpu.get_special_registers();

	return {sregs.fs.base, sregs.gs.base};
}
void Machine::set_tls_base(__u64 baseaddr)
{
	auto& sregs = vcpu.get_special_registers();

	sregs.fs.base = baseaddr;

	vcpu.set_special_registers(sregs);
}

void Machine::prepare_copy_on_write(size_t max_work_mem, uint64_t shared_memory_boundary)
{
	assert(this->m_prepped == false);
	this->m_prepped = true;
	/* Make each writable page read-only, causing page fault.
	   any page after the @shared_memory_boundary is untouched,
	   effectively turning it into a shared memory area for all. */
	if (shared_memory_boundary == 0)
		shared_memory_boundary = UINT64_MAX;
	foreach_page_makecow(this->memory, kernel_end_address(), shared_memory_boundary);

	// Visualizing the page tables after makecow should show that all
	// relevant user-writable pages have been made read-only and cloneable
	//print_pagetables(this->memory);

	/* Make this machine runnable again using itself
	   as the master VM. */
	memory.banks.set_max_pages(max_work_mem / PAGE_SIZE);
	/* Without working memory we will not be able to make
	   this master VM usable after prepare_copy_on_write. */
	if (max_work_mem == 0)
		return;
	/* This call makes this VM usable after making every page in the
	   page tables read-only, enabling memory through page faults. */
	this->setup_cow_mode(this);
}
void Machine::setup_cow_mode(const Machine* other)
{
	/* Clone master PML4 page. We use the fixed PT_ADDR
	   directly in order to avoid duplicating the memory banked
	   page tables that allow the master VM to execute code
	   separately from its forks, while sharing a master page table. */
	auto pml4 = memory.new_page();
	tinykvm::page_duplicate(pml4.pmem,
		other->memory.page_at(other->memory.physbase + PT_ADDR)); // Intentional!
	memory.page_tables = pml4.addr;

	/* Zero a new page for IST stack */
	// XXX: This is not strictly necessary as we can
	// hand-write a custom handler that only triggers on actual writes?
	// The problem is that in order to handle interrupts, we need these
	// pages to already be there. It would have been much easier with
	// stackless interrupts, to be honest. Something to think about?
	// XXX: In theory we can avoid initializing one of these pages
	// until the guest asks for a certain level of concurrency.
	memory.get_writable_page(memory.physbase + IST_ADDR, PDE64_RW, true);
	//memory.get_writable_page(IST2_ADDR, PDE64_RW, true);

	struct kvm_sregs sregs = other->get_special_registers();

	/* Page table entry will be cloned at the start */
	sregs.cr3 = memory.page_tables;
	sregs.cr0 &= ~CR0_WP; // XXX: Fix me!

	vcpu.set_special_registers(sregs);
	//print_pagetables(this->memory);
#if 0
	/* It shouldn't be identity-mapped anymore */
	assert(translate(memory.physbase + IST_ADDR) != IST_ADDR);
	//printf("Translate 0x%lX => 0x%lX\n", IST_ADDR, translate(IST_ADDR));
	page_at(memory, memory.physbase + IST_ADDR, [] (auto, auto& entry, auto) {
		assert(entry & (PDE64_PRESENT | PDE64_RW | PDE64_NX));
		(void) entry;
	});
#endif


	/* This blocking message passes the new special registers
	   to every existing vCPU used in multi-processing. In the
	   future there may be more stuff we need to pass onto the
	   vCPUs, but for now we only need updated sregs. */
	if (m_smp != nullptr) {
		smp_vcpu_broadcast([sregs] (auto& cpu) {
			cpu.set_special_registers(sregs);
		});
	}
}

void Machine::print_pagetables() const {
	tinykvm::print_pagetables(this->memory);
}
void Machine::print_exception_handlers() const
{
	const auto& sregs = vcpu.get_special_registers();
	tinykvm::print_exception_handlers(memory.at(sregs.idt.base));
}

Machine::address_t Machine::entry_address_if_usermode() const noexcept
{
	// Check if we are already usermode
	// If we are, we return userfunc which is safe to jump to
#ifdef TINYKVM_USE_SYNCED_SREGS
	// WARNING: This shortcut *requires* KVM_SYNC_X86_SREGS
	if (this->vcpu.get_special_registers().cs.dpl == 0x3)
		return usercode_header().translated_vm_userentry(memory);
#endif
	// If not, return the "dummy syscall" entry address
	// Returning from a dummy syscall leaves us in usermode
	return usercode_header().translated_vm_reentry(memory);
}

Machine::address_t Machine::entry_address() const noexcept {
	return usercode_header().translated_vm_entry(memory);
}
Machine::address_t Machine::reentry_address() const noexcept {
	return usercode_header().translated_vm_reentry(memory);
}
Machine::address_t Machine::exit_address() const noexcept {
	return usercode_header().translated_vm_rexit(memory);
}

} // tinykvm
