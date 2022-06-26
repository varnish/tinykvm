#include "machine.hpp"

#include <cassert>
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/signal.h>
#include "page_streaming.hpp"
#include "kernel/amd64.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
#include "kernel/lapic.hpp"
#include "kernel/tss.hpp"
#include "kernel/paging.hpp"
#include "kernel/memory_layout.hpp"
#include "kernel/usercode.hpp"
extern "C" int gettid();
extern "C" int close(int);
static void unused_usr_handler(int) {}

namespace tinykvm {
	static struct kvm_sregs master_sregs;
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
	signal(SIGUSR1, unused_usr_handler);

	struct sigevent sigev;
	sigev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
	sigev.sigev_signo = SIGUSR1;
	sigev._sigev_un._tid = gettid();

	timer_t timer_id;
	if (timer_create(CLOCK_MONOTONIC, &sigev, &timer_id) < 0)
		throw MachineException("Unable to create timeout timer");
	return timer_id;
}

void Machine::vCPU::init(int id, Machine& machine, const MachineOptions& options)
{
	this->cpu_id = id;
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->cpu_id);
	this->machine = &machine;
	if (UNLIKELY(this->fd < 0)) {
		machine_exception("Failed to KVM_CREATE_VCPU");
	}
	this->timer_id = create_vcpu_timer();

	kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(kvm_run == MAP_FAILED)) {
		machine_exception("Failed to create KVM run-time mapped memory");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		machine_exception("KVM_SET_CPUID2 failed");
	}

	static bool minit = false;
	if (!minit) {
		minit = true;
		if (ioctl(this->fd, KVM_GET_SREGS, &master_sregs) < 0) {
			machine_exception("KVM_GET_SREGS failed");
		}
		master_sregs.cr3 = PT_ADDR;
		master_sregs.cr4 =
			CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE | CR4_FSGSBASE;
		master_sregs.cr0 =
			CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
		master_sregs.efer =
			EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
		setup_amd64_segment_regs(master_sregs, GDT_ADDR);
		master_sregs.gs.base = usercode_header().vm64_cpuid;
		setup_amd64_tss_regs(master_sregs, TSS_ADDR);
		setup_amd64_exception_regs(master_sregs, IDT_ADDR);

		if (ioctl(this->fd, KVM_GET_XCRS, &master_xregs) < 0) {
			machine_exception("KVM_GET_XCRS failed");
		}
		/* Enable AVX and AVX512 instructions */
		master_xregs.xcrs[0].xcr = 0;
		master_xregs.xcrs[0].value |= 0x7; // FPU, SSE, YMM
#  ifdef KVM_AVX512
		master_xregs.xcrs[0].value |= 0xE0; // AVX512
#  endif
		master_xregs.nr_xcrs = 1;
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		machine_exception("KVM_SET_XCRS failed");
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
//	msrs.entries[2].index = AMD64_MSR_APICBASE;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().vm64_syscall;
//	msrs.entries[2].data  = 0xfee00000 | AMD64_MSR_XAPIC_ENABLE;

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < msrs.nmsrs) {
		machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR/X2APIC");
	}
}

void Machine::vCPU::smp_init(int id, Machine& machine)
{
	this->cpu_id = id;
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->cpu_id);
	this->machine = &machine;
	if (UNLIKELY(this->fd < 0)) {
		machine_exception("Failed to KVM_CREATE_VCPU");
	}
	this->timer_id = create_vcpu_timer();

	kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(kvm_run == MAP_FAILED)) {
		machine_exception("Failed to create KVM run-time mapped memory");
	}

	const kvm_mp_state state {
		.mp_state = KVM_MP_STATE_RUNNABLE
	};
	if (ioctl(this->fd, KVM_SET_MP_STATE, &state) < 0) {
		machine_exception("KVM_SET_MP_STATE failed");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		machine_exception("KVM_SET_CPUID2 failed");
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		machine_exception("KVM_SET_XCRS failed");
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
	//msrs.entries[2].index = AMD64_MSR_APICBASE;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().vm64_syscall;
	//msrs.entries[2].data  = 0xfee00000 | AMD64_MSR_X2APIC_ENABLE;

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < msrs.nmsrs) {
		machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR/X2APIC");
	}
}

void Machine::vCPU::deinit()
{
	if (this->fd > 0) {
		close(this->fd);
	}
	if (kvm_run != nullptr) {
		munmap(kvm_run, vcpu_mmap_size);
	}

	timer_delete(this->timer_id);
}

tinykvm_x86regs Machine::vCPU::registers() const
{
	struct tinykvm_x86regs regs;
	if (ioctl(this->fd, KVM_GET_REGS, &regs) < 0) {
		machine_exception("KVM_SET_REGS failed");
	}
	return regs;
}
void Machine::vCPU::assign_registers(const struct tinykvm_x86regs& regs)
{
	if (ioctl(this->fd, KVM_SET_REGS, &regs) < 0) {
		machine_exception("KVM_SET_REGS failed");
	}
}
void Machine::vCPU::get_special_registers(struct kvm_sregs& sregs) const
{
	if (ioctl(this->fd, KVM_GET_SREGS, &sregs) < 0) {
		machine_exception("KVM_GET_SREGS failed");
	}
}
void Machine::vCPU::set_special_registers(const struct kvm_sregs& sregs)
{
	if (ioctl(this->fd, KVM_SET_SREGS, &sregs) < 0) {
		machine_exception("KVM_GET_SREGS failed");
	}
}

std::string_view Machine::vCPU::io_data() const
{
	char *p = (char *) kvm_run;
	return {&p[kvm_run->io.data_offset], kvm_run->io.size};
}

void Machine::setup_long_mode(const Machine* other, const MachineOptions& options)
{
	if (other == nullptr) // Main VM
	{
		setup_amd64_exceptions(
			IDT_ADDR, memory.at(IDT_ADDR), memory.at(INTR_ASM_ADDR));
		setup_amd64_segments(GDT_ADDR, memory.at(GDT_ADDR));
		setup_amd64_tss(TSS_ADDR, memory.at(TSS_ADDR), memory.at(GDT_ADDR));
		setup_amd64_tss_smp(memory.at(TSS_SMP_ADDR));
		/* Userspace entry/exit code */
		setup_vm64_usercode(memory.at(USER_ASM_ADDR));

		this->m_kernel_end = setup_amd64_paging(memory, m_binary);

		vcpu.set_special_registers(master_sregs);
	}
	else // Forked VM
	{
		setup_cow_mode(other);
	}
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);

	return {sregs.fs.base, sregs.gs.base};
}
void Machine::set_tls_base(__u64 baseaddr)
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);

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
	foreach_page_makecow(this->memory, shared_memory_boundary);
	//print_pagetables(this->memory);
	/* Cache all the special registers, which we will use on forks */
	if (this->cached_sregs == nullptr) {
		this->cached_sregs = new kvm_sregs {};
	}
	get_special_registers(*this->cached_sregs);

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
	auto pml4 = memory.new_page(0x0);
	tinykvm::page_duplicate(pml4.pmem, other->memory.page_at(PT_ADDR));
	memory.page_tables = pml4.addr;

	/* Zero a new page for IST stack */
	// XXX: This is not strictly necessary as we can
	// hand-write a custom handler that only triggers on actual writes?
	// The problem is that in order to handle interrupts, we need these
	// pages to already be there. It would have been much easier with
	// stackless interrupts, to be honest. Something to think about?
	// XXX: In theory we can avoid initializing one of these pages
	// until the guest asks for a certain level of concurrency.
	memory.get_writable_page(IST_ADDR, true);
	memory.get_writable_page(IST2_ADDR, true);

	/* Inherit the special registers of the master machine.
	   Ensures that special registers can never be corrupted. */
	assert(other->cached_sregs);
	struct kvm_sregs sregs = *other->cached_sregs;

	/* Page table entry will be cloned at the start */
	sregs.cr3 = memory.page_tables;
	sregs.cr0 &= ~CR0_WP; // XXX: Fix me!

	vcpu.set_special_registers(sregs);
	//print_pagetables(this->memory);
#if 0
	/* It shouldn't be identity-mapped anymore */
	assert(translate(IST_ADDR) != IST_ADDR);
	//printf("Translate 0x%lX => 0x%lX\n", IST_ADDR, translate(IST_ADDR));
	page_at(memory, IST_ADDR, [] (auto, auto& entry, auto) {
		assert(entry & (PDE64_PRESENT | PDE64_RW | PDE64_NX));
		(void) entry;
	});
#endif

	/* This blocking message passes the new special registers
	   to every existing vCPU used in multi-processing. In the
	   future there may be more stuff we need to pass onto the
	   vCPUs, but for now we only need updated sregs. */
	for (auto& cpu : m_cpus) {
		cpu.blocking_message([sregs] (auto& cpu) {
			cpu.set_special_registers(sregs);
		});
	}
}

void Machine::print_pagetables() const {
	tinykvm::print_pagetables(this->memory);
}
void Machine::print_exception_handlers() const
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);
	tinykvm::print_exception_handlers(memory.at(sregs.idt.base));
}

Machine::address_t Machine::entry_address() const noexcept {
	return usercode_header().vm64_entry;
}
Machine::address_t Machine::exit_address() const noexcept {
	return usercode_header().vm64_rexit;
}

} // tinykvm
