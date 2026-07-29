#include "../machine.hpp"

#include "memory_layout.hpp"
#include "paging.hpp"
#include "../page_streaming.hpp"
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

extern "C" int close(int);
extern "C" void tinykvm_timer_signal_handler(int);

#ifndef SYS_gettid
#error "SYS_gettid unavailable on this system"
#endif
#define gettid() ((pid_t)syscall(SYS_gettid))

struct ksigevent
{
	union sigval sigev_value;
	int sigev_signo;
	int sigev_notify;
	int sigev_tid;
};

namespace tinykvm {
static long vcpu_mmap_size = 0;
static int vm_ipa_bits = 40; /* KVM's legacy default IPA size */

/* Defined below; forward-declared for vCPU::flush_pending_guest_tlb(). */
static void arm64_flush_guest_tlb(vCPU& cpu);

int arm64_vm_ipa_bits()
{
	return vm_ipa_bits;
}
static constexpr uint64_t ARM64_PSTATE_MODE_MASK = 0xFULL;
static constexpr uint64_t ARM64_PSTATE_EL0T = 0x0;
static constexpr uint64_t ARM64_PSTATE_EL1H = 0x5;
static constexpr uint64_t ARM64_DESC_VALID = 1ULL << 0;
static constexpr uint64_t ARM64_DESC_TABLE = 1ULL << 1;
static constexpr uint64_t ARM64_DESC_ADDR_MASK = 0x0000FFFFFFFFF000ULL;

TINYKVM_COLD()
void initialize_vcpu_stuff(int kvm_fd)
{
	vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		throw MachineException("Failed to KVM_GET_VCPU_MMAP_SIZE");
	}
	/* VMs are created with the host's maximum IPA size (create_kvm_vm);
	   TCR_EL1.IPS must be programmed to match or stage-1 walks fault on
	   physical outputs above 4GB (file-backed mmap regions, &c). */
	const int ipa = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
	if (ipa > 0) {
		vm_ipa_bits = ipa;
	}
}

void* Machine::create_vcpu_timer()
{
	signal(SIGUSR2, tinykvm_timer_signal_handler);

	struct ksigevent sigev {};
	sigev.sigev_notify = SIGEV_SIGNAL | SIGEV_THREAD_ID;
	sigev.sigev_signo = SIGUSR2;
	sigev.sigev_tid = gettid();

	timer_t timer_id {};
	if (timer_create(CLOCK_MONOTONIC, (struct sigevent *)&sigev, &timer_id) < 0)
		throw MachineException("Unable to create timeout timer");
	return timer_id;
}

void vCPU::init(int kvm_vcpu_id, int guest_cpu_index, Machine& machine, const MachineOptions& options)
{
	this->kvm_vcpu_id = kvm_vcpu_id;
	this->guest_cpu_index = guest_cpu_index;
	this->last_fault_address = 0;
	this->m_machine = &machine;

	if (this->fd < 0) {
		this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->kvm_vcpu_id);
		if (UNLIKELY(this->fd < 0)) {
			Machine::machine_exception("Failed to KVM_CREATE_VCPU");
		}

		struct kvm_vcpu_init init {};
		if (ioctl(machine.fd, KVM_ARM_PREFERRED_TARGET, &init) < 0) {
			Machine::machine_exception("KVM_ARM_PREFERRED_TARGET failed", errno);
		}
		if (ioctl(this->fd, KVM_ARM_VCPU_INIT, &init) < 0) {
			Machine::machine_exception("KVM_ARM_VCPU_INIT failed", errno);
		}
	}
	if (this->timer_id == nullptr) {
		this->timer_id = Machine::create_vcpu_timer();
		this->timer_tid = gettid();
	}
	/* Defer the kvm_run mapping to the first run when lazy_vcpu_mmap is set:
	   ensure_kvm_run() (run_once) creates it on demand. A fork that never runs
	   then never pays the mapping's host VMA -- the property vm_group_vma_flat
	   pins for pooled seats, but honoured here too so a lazy master/plain fork
	   behaves the same. */
	if (this->kvm_run == nullptr && !options.lazy_vcpu_mmap) {
		kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
		if (UNLIKELY(kvm_run == MAP_FAILED)) {
			Machine::machine_exception("Failed to create KVM run-time mapped memory");
		}
	}
}

void vCPU::init_from_seat(VmGroupSeat& seat, Machine& machine,
	const MachineOptions& options)
{
	this->kvm_vcpu_id = seat.kvm_vcpu_id;
	this->guest_cpu_index = 0;
	this->last_fault_address = 0;
	this->m_machine = &machine;

	/* The seat's vCPU is created when the group materializes the seat and is
	   adopted, never created, here -- see the AMD64 twin (vcpu.cpp) for why
	   materialization owns KVM_CREATE_VCPU rather than this path. */
	if (UNLIKELY(seat.vcpu_fd < 0)) {
		Machine::machine_exception("VM group seat has no vCPU", seat.kvm_vcpu_id);
	}
	this->fd = seat.vcpu_fd;

	/* Rebind the seat's execution timer to this thread when a different thread
	   created it: the timer is thread-bound (SIGEV_THREAD_ID) but the seat is
	   handed to whichever thread takes it next. Same reasoning, and the same
	   cost, as the AMD64 path and Machine::migrate_to_this_thread(). */
	const pid_t this_tid = gettid();
	if (seat.timer_id != nullptr && seat.owner_tid != this_tid) {
		timer_delete((timer_t)seat.timer_id);
		seat.timer_id = nullptr;
		seat.owner_tid = 0;
	}
	if (seat.timer_id == nullptr) {
		seat.timer_id = Machine::create_vcpu_timer();
		seat.owner_tid = this_tid;
	}
	this->timer_id = seat.timer_id;
	this->timer_tid = seat.owner_tid;

	/* kvm_run belongs to the seat and outlives every tenant (torn down only
	   when the group retires the seat). Adopt the seat's existing mapping if a
	   prior tenant made it. Otherwise, under lazy_vcpu_mmap, defer to the first
	   run (ensure_kvm_run) so a pooled fork that never runs costs no host VMA --
	   the vm_group_vma_flat property; without lazy, map it now and record it on
	   the seat. ensure_kvm_run() writes the seat back either way. */
	if (seat.kvm_run != nullptr) {
		this->kvm_run = (struct kvm_run *)seat.kvm_run;
	} else if (!options.lazy_vcpu_mmap) {
		this->kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
		if (UNLIKELY(this->kvm_run == MAP_FAILED)) {
			Machine::machine_exception("Failed to map VM group seat kvm_run");
		}
		seat.kvm_run = this->kvm_run;
	}

	/* One-time per-seat vCPU bring-up. The AMD64 twin issues KVM_SET_CPUID2
	   here; the ARM analogue is KVM_ARM_VCPU_INIT against the host's preferred
	   target. It runs once per seat (KVM rejects re-init after a run the same
	   way it rejects re-CPUID). The fork's real register/sysreg/pagetable state
	   is applied immediately after, by setup_cow_mode() and set_registers() in
	   the fork constructor, so INIT's reset defaults never reach the guest. */
	if (!seat.vcpu_initialized) {
		seat.vcpu_initialized = true;
		struct kvm_vcpu_init init {};
		if (ioctl(machine.fd, KVM_ARM_PREFERRED_TARGET, &init) < 0) {
			Machine::machine_exception("KVM_ARM_PREFERRED_TARGET failed", errno);
		}
		if (ioctl(this->fd, KVM_ARM_VCPU_INIT, &init) < 0) {
			Machine::machine_exception("KVM_ARM_VCPU_INIT failed", errno);
		}
	}

	/* This vCPU object is freshly constructed with its (pooled) Machine, so the
	   register cache is already clean; make that a stated invariant rather than
	   an inherited one, since a stale cache would serve a sibling's registers. */
	this->m_regs_cached = false;
	this->m_regs_dirty = false;
}

void vCPU::detach_to_seat(VmGroupSeat& seat) noexcept
{
	/* Hand fd, kvm_run and timer back to the seat without closing or unmapping
	   anything: a struct kvm consumes vCPU capacity permanently, so closing the
	   fd would burn the seat rather than free it. The next tenant re-adopts all
	   three in init_from_seat(). No shadow-register teardown as on AMD64 -- ARM
	   has no lazy mapping, so there is nothing owned to delete. */
	if (this->fd >= 0) {
		seat.vcpu_fd   = this->fd;
		seat.kvm_run   = this->kvm_run;
		seat.timer_id  = this->timer_id;
		seat.owner_tid = this->timer_tid;
	}
	this->fd = -1;
	this->kvm_run = nullptr;
	this->timer_id = nullptr;
	this->timer_tid = 0;
	this->m_regs_cached = false;
	this->m_regs_dirty = false;
}

void vCPU::ensure_kvm_run()
{
	if (LIKELY(this->kvm_run != nullptr))
		return;
	this->kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(this->kvm_run == MAP_FAILED)) {
		Machine::machine_exception("Failed to lazily map kvm_run");
	}
	/* A pooled member's mapping belongs to its seat so the next tenant adopts
	   it rather than re-mapping: one host VMA per seat, never per tenant. Same
	   write-back the AMD64 lazily_map_kvm_run() does. */
	if (UNLIKELY(this->machine().m_seat != nullptr)) {
		this->machine().m_seat->kvm_run = this->kvm_run;
	}
}

void vCPU::flush_pending_guest_tlb()
{
	if (LIKELY(!this->machine().m_pending_tlb_flush))
		return;
	/* Clear before running the stub: arm64_flush_guest_tlb() runs the guest,
	   re-entering run_once() -> here, and the cleared flag stops it recursing. */
	this->machine().m_pending_tlb_flush = false;
	arm64_flush_guest_tlb(*this);
}

void vCPU::smp_init(int, Machine&)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void vCPU::deinit()
{
	if (this->fd > 0) {
		close(this->fd);
		this->fd = -1;
	}
	if (kvm_run != nullptr) {
		munmap(kvm_run, vcpu_mmap_size);
		kvm_run = nullptr;
	}
	if (this->timer_id != nullptr) {
		timer_delete((timer_t)this->timer_id);
		this->timer_id = nullptr;
	}
}

static uint64_t core_reg_id(uint64_t reg, uint64_t size)
{
	return KVM_REG_ARM64 | size | KVM_REG_ARM_CORE | reg;
}

static uint64_t core_reg_id(uint64_t reg)
{
	return core_reg_id(reg, KVM_REG_SIZE_U64);
}

static uint64_t core_gpr_reg_id(size_t index)
{
	return core_reg_id(KVM_REG_ARM_CORE_REG(regs.regs)
		+ index * sizeof(__u64) / sizeof(__u32));
}

static uint64_t core_fpreg_reg_id(size_t index)
{
	return core_reg_id(KVM_REG_ARM_CORE_REG(fp_regs.vregs)
		+ index * sizeof(__uint128_t) / sizeof(__u32), KVM_REG_SIZE_U128);
}

static uint64_t core_fpstatus_reg_id(uint64_t reg)
{
	return core_reg_id(reg, KVM_REG_SIZE_U32);
}

static void get_one_reg(int fd, uint64_t id, __u64& value)
{
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)&value,
	};
	if (ioctl(fd, KVM_GET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_GET_ONE_REG failed", errno);
	}
}

static void get_one_reg_data(int fd, uint64_t id, void* data)
{
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)data,
	};
	if (ioctl(fd, KVM_GET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_GET_ONE_REG failed", errno);
	}
}

static void set_one_reg(int fd, uint64_t id, uint64_t value)
{
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)&value,
	};
	if (ioctl(fd, KVM_SET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_SET_ONE_REG failed", errno);
	}
}

static void set_one_reg_data(int fd, uint64_t id, const void* data)
{
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)data,
	};
	if (ioctl(fd, KVM_SET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_SET_ONE_REG failed", errno);
	}
}

static uint64_t sys_reg_id(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG
		| (((uint64_t)op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK)
		| (((uint64_t)op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK)
		| (((uint64_t)crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK)
		| (((uint64_t)crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK)
		| (((uint64_t)op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK);
}

static tinykvm_arm64regs get_arm64_regs(int fd)
{
	tinykvm_arm64regs regs {};
	for (size_t i = 0; i < 31; i++) {
		get_one_reg(fd, core_gpr_reg_id(i), regs.regs[i]);
	}
	get_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.pstate)), regs.pstate);
	/* tinykvm guests run user code at EL0. When the host inspects registers
	   it is almost always servicing a trap, i.e. the vCPU is parked at EL1h in
	   the exception vector. The EL0 user context the host (and the cooperative
	   thread scheduler) cares about then lives in:
	     - regs.pc  <- ELR_EL1   (the core PC is the vector stub at 0x84xx)
	     - regs.sp  <- SP_EL0     (== user_pt_regs.sp; sp_el1 is vector scratch)
	   At EL0t (e.g. a stopped guest before vmcall/reset) the core PC/SP already
	   hold the user values. Reading sp_el1 here was a latent bug: harmless for
	   single-threaded guests (handlers only touch GPRs) but it made the thread
	   scheduler switch the wrong banked SP, so cloned threads ran on the
	   parent's stack. */
	const bool el1h = (regs.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL1H;
	const auto pc_reg = el1h
		? KVM_REG_ARM_CORE_REG(elr_el1)
		: KVM_REG_ARM_CORE_REG(regs.pc);
	get_one_reg(fd, core_reg_id(pc_reg), regs.pc);
	get_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.sp)), regs.sp);
	return regs;
}

static void set_arm64_regs(int fd, const tinykvm_arm64regs& regs)
{
	for (size_t i = 0; i < 31; i++) {
		set_one_reg(fd, core_gpr_reg_id(i), regs.regs[i]);
	}
	set_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.pstate)), regs.pstate);
	/* Mirror get_arm64_regs(): at EL1h the user PC/SP are ELR_EL1 and SP_EL0,
	   and the core PC must be left pointing at the exception vector so it
	   eret's back to the (possibly host-modified) ELR_EL1. */
	const bool el1h = (regs.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL1H;
	const auto pc_reg = el1h
		? KVM_REG_ARM_CORE_REG(elr_el1)
		: KVM_REG_ARM_CORE_REG(regs.pc);
	set_one_reg(fd, core_reg_id(pc_reg), regs.pc);
	set_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.sp)), regs.sp);
}

/* Run the EL1 TLB-flush stub for one VM entry. The host cannot invalidate
   the guest's stage-1 TLB through KVM, so after rewriting page tables or
   switching TTBR0_EL1 the vCPU would keep using translations from the
   previous run (e.g. CoW pages in recycled memory banks after reset_to).
   Only PC, PSTATE and x9 are clobbered by the stub; save/restore just
   those with raw one-reg ioctls to keep the reset path cheap. */
static void arm64_flush_guest_tlb(vCPU& cpu)
{
	const uint64_t PC_ID = core_reg_id(KVM_REG_ARM_CORE_REG(regs.pc));
	const uint64_t PSTATE_ID = core_reg_id(KVM_REG_ARM_CORE_REG(regs.pstate));
	const uint64_t X9_ID = core_gpr_reg_id(9);

	cpu.flush_registers();
	__u64 saved_pc = 0, saved_pstate = 0, saved_x9 = 0;
	get_one_reg(cpu.fd, PC_ID, saved_pc);
	get_one_reg(cpu.fd, PSTATE_ID, saved_pstate);
	get_one_reg(cpu.fd, X9_ID, saved_x9);

	set_one_reg(cpu.fd, PC_ID, TLB_FLUSH_ADDR);
	set_one_reg(cpu.fd, PSTATE_ID, ARM64_PSTATE_EL1H | 0x3C0 /* DAIF masked */);
	cpu.run(0);

	set_one_reg(cpu.fd, PC_ID, saved_pc);
	set_one_reg(cpu.fd, PSTATE_ID, saved_pstate);
	set_one_reg(cpu.fd, X9_ID, saved_x9);
}

static uint64_t clone_arm64_page_table(vMemory& dst, const vMemory& src,
	uint64_t table_addr, unsigned level)
{
	auto table = dst.new_page();
	tinykvm::page_duplicate(table.pmem, src.page_at(table_addr));
	if (level < 3) {
		for (size_t i = 0; i < 512; i++) {
			uint64_t& entry = table.pmem[i];
			if ((entry & (ARM64_DESC_VALID | ARM64_DESC_TABLE))
				== (ARM64_DESC_VALID | ARM64_DESC_TABLE)) {
				const uint64_t child_addr = entry & ARM64_DESC_ADDR_MASK;
				const uint64_t cloned_child =
					clone_arm64_page_table(dst, src, child_addr, level + 1);
				entry = (entry & ~ARM64_DESC_ADDR_MASK) | cloned_child;
			}
		}
	}
	return table.addr;
}

const tinykvm_regs& vCPU::registers() const
{
	if (!m_regs_cached) {
		m_cached_regs = get_arm64_regs(this->fd);
		m_regs_cached = true;
	}
	return m_cached_regs;
}

tinykvm_regs& vCPU::registers()
{
	if (!m_regs_cached) {
		m_cached_regs = get_arm64_regs(this->fd);
		m_regs_cached = true;
	}
	m_regs_dirty = true;
	return m_cached_regs;
}

void vCPU::set_registers(const struct tinykvm_regs& regs)
{
	m_cached_regs = regs;
	m_regs_cached = true;
	m_regs_dirty = true;
}

void vCPU::flush_registers() const
{
	if (m_regs_cached && m_regs_dirty) {
		set_arm64_regs(this->fd, m_cached_regs);
		m_regs_dirty = false;
	}
}

void vCPU::invalidate_register_cache() const
{
	m_regs_cached = false;
	m_regs_dirty = false;
}

tinykvm_fpuregs vCPU::fpu_registers() const
{
	static_assert(sizeof(tinykvm_fpuregs::storage) == sizeof(user_fpsimd_state),
		"ARM64 FP/SIMD storage must match user_fpsimd_state");

	user_fpsimd_state state {};
	for (size_t i = 0; i < 32; i++) {
		get_one_reg_data(this->fd, core_fpreg_reg_id(i), &state.vregs[i]);
	}
	get_one_reg_data(this->fd, core_fpstatus_reg_id(KVM_REG_ARM_CORE_REG(fp_regs.fpsr)),
		&state.fpsr);
	get_one_reg_data(this->fd, core_fpstatus_reg_id(KVM_REG_ARM_CORE_REG(fp_regs.fpcr)),
		&state.fpcr);

	tinykvm_fpuregs regs {};
	std::memcpy(regs.storage, &state, sizeof(state));
	return regs;
}

void vCPU::set_fpu_registers(const struct tinykvm_fpuregs& regs)
{
	user_fpsimd_state state {};
	std::memcpy(&state, regs.storage, sizeof(state));
	for (size_t i = 0; i < 32; i++) {
		set_one_reg_data(this->fd, core_fpreg_reg_id(i), &state.vregs[i]);
	}
	set_one_reg_data(this->fd, core_fpstatus_reg_id(KVM_REG_ARM_CORE_REG(fp_regs.fpsr)),
		&state.fpsr);
	set_one_reg_data(this->fd, core_fpstatus_reg_id(KVM_REG_ARM_CORE_REG(fp_regs.fpcr)),
		&state.fpcr);
}

const kvm_sregs& vCPU::get_special_registers() const
{
	static const kvm_sregs sregs {};
	return sregs;
}

kvm_sregs& vCPU::get_special_registers()
{
	static kvm_sregs sregs {};
	return sregs;
}

void vCPU::set_special_registers(const kvm_sregs&)
{
}

std::string_view vCPU::io_data() const
{
	return {};
}

void Machine::setup_long_mode(const MachineOptions&)
{
	arm64_setup_el1_mmu(*this, this->vcpu);
	this->m_kernel_end = VCPU_TABLE_ADDR + VCPU_TABLE_SIZE;
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	const uint64_t TPIDR_EL0 = sys_reg_id(3, 3, 13, 0, 2);
	__u64 value = 0;
	get_one_reg(this->vcpu.fd, TPIDR_EL0, value);
	return {value, 0};
}

void Machine::set_tls_base(__u64 baseaddr)
{
	const uint64_t TPIDR_EL0 = sys_reg_id(3, 3, 13, 0, 2);
	set_one_reg(this->vcpu.fd, TPIDR_EL0, baseaddr);
}

uint64_t vCPU::vcpu_table_addr() const noexcept
{
	return machine().memory.physbase + VCPU_TABLE_ADDR
		+ sizeof(PerVCPUTable) * this->guest_cpu_index;
}

void vCPU::set_vcpu_table_at(unsigned index, int value)
{
	if (index >= 4)
		throw MachineException("Invalid vCPU table index", index);
	const auto addr = this->vcpu_table_addr() + index * sizeof(int);
	auto* page = machine().main_memory().get_userpage_at(addr & ~0xFFFull);
	const auto offset = addr & 0xFFFull;
	*((int*)&page[offset]) = value;
}

void Machine::prepare_copy_on_write(size_t max_work_mem,
	uint64_t shared_memory_boundary, bool split_accessed_hugepages)
{
	this->m_prepped = true;
	this->m_prepared_fpu_regs = this->fpu_registers();
	if (shared_memory_boundary == 0)
		shared_memory_boundary = UINT64_MAX;

	memory.banks.set_max_pages(max_work_mem / PAGE_SIZE, 0u);
	if (max_work_mem == 0) {
		memory.main_memory_writes = false;
		memory.page_tables = memory.physbase + PT_ADDR;
		foreach_page_makecow(this->memory, kernel_end_address(),
			shared_memory_boundary, split_accessed_hugepages);
		set_one_reg(this->vcpu.fd, sys_reg_id(3, 0, 2, 0, 0), memory.page_tables);
		arm64_flush_guest_tlb(this->vcpu);
		return;
	}

	foreach_page_makecow(this->memory, kernel_end_address(),
		shared_memory_boundary, split_accessed_hugepages);
	this->setup_cow_mode(this);
}

void Machine::setup_cow_mode(const Machine* other)
{
	memory.page_tables = clone_arm64_page_table(memory, other->memory,
		other->memory.page_tables, 1);

	const uint64_t sysregs[] {
		sys_reg_id(3, 0, 10, 2, 0), // MAIR_EL1
		sys_reg_id(3, 0, 2, 0, 2),  // TCR_EL1
		sys_reg_id(3, 0, 1, 0, 0),  // SCTLR_EL1
		sys_reg_id(3, 0, 1, 0, 2),  // CPACR_EL1
		sys_reg_id(3, 0, 12, 0, 0), // VBAR_EL1
	};
	for (uint64_t reg_id : sysregs) {
		__u64 value = 0;
		get_one_reg(other->vcpu.fd, reg_id, value);
		set_one_reg(this->vcpu.fd, reg_id, value);
	}
	set_one_reg(this->vcpu.fd, sys_reg_id(3, 0, 2, 0, 0), memory.page_tables);

	if (m_smp != nullptr) {
		const uint64_t ttbr0 = memory.page_tables;
		smp_vcpu_broadcast([ttbr0] (auto& cpu) {
			set_one_reg(cpu.fd, sys_reg_id(3, 0, 2, 0, 0), ttbr0);
		});
	}
	/* The stub broadcasts (tlbi vmalle1is), covering SMP vCPUs too. Deferred to
	   the first run_once() (flush_pending_guest_tlb): the flush is a guest run,
	   so running it here would map kvm_run at construction and cost a warm-
	   reserve fork a host VMA it may never use. Correctness is unchanged --
	   every guest execution funnels through run_once(), which flushes first. */
	this->m_pending_tlb_flush = true;
}

void Machine::print_pagetables() const
{
	tinykvm::print_pagetables(this->memory);
}

void Machine::print_exception_handlers() const
{
}

bool vCPU::is_usermode() const
{
	const auto& regs = this->registers();
	return (regs.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL0T;
}

bool vCPU::is_kernelmode() const
{
	return !is_usermode();
}

void vCPU::enter_usermode()
{
	auto regs = this->registers();
	if ((regs.pstate & ARM64_PSTATE_MODE_MASK) != ARM64_PSTATE_EL0T) {
		regs.pstate = (regs.pstate & ~ARM64_PSTATE_MODE_MASK) | ARM64_PSTATE_EL0T;
		this->set_registers(regs);
	}
}

void Machine::enter_usermode()
{
	vcpu.enter_usermode();
}

tinykvm_regs vCPU::usermode_frame_from_syscall() const
{
	/* Build a resumable EL0 (usermode) register frame from a vCPU that is
	   currently parked *inside* a syscall handler (EL1). This MUST be called
	   while the handler is on the stack -- i.e. from a syscall/fds callback --
	   because the general-purpose registers x0..x30 still hold the user's
	   pristine values then. (After the run loop returns, the deferred
	   PC-increment re-enters the EL1 trampoline, which clobbers scratch
	   registers like x1.) The user's return PC and stack are banked in ELR_EL1
	   and SP_EL0; the GP registers are not banked, so we keep them as-is. */
	auto regs = this->registers();
	__u64 user_pc = 0, user_sp = 0;
	get_one_reg(this->fd, core_reg_id(KVM_REG_ARM_CORE_REG(elr_el1)), user_pc);
	get_one_reg(this->fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.sp)), user_sp);
	regs.pc     = user_pc;   // ELR_EL1: instruction after the user's SVC
	regs.sp     = user_sp;   // SP_EL0:  the user stack (unchanged by the trap)
	regs.pstate = (regs.pstate & ~ARM64_PSTATE_MODE_MASK) | ARM64_PSTATE_EL0T;
	return regs;
}

tinykvm_regs Machine::usermode_frame_from_syscall() const
{
	return vcpu.usermode_frame_from_syscall();
}

uint64_t Machine::tpidr_el0() const
{
	__u64 t = 0;
	get_one_reg(this->vcpu.fd, sys_reg_id(3, 3, 13, 0, 2), t);
	return t;
}

void Machine::set_tpidr_el0(uint64_t value)
{
	/* The user-space thread pointer (TLS base). A fork's MultiThreading reset
	   rebuilds thread state and clears this; for a fork resumed directly into
	   EL0 user code (not via vmcall) it must be restored to the master's value
	   or the guest's first TLS access (errno, &c) faults. */
	set_one_reg(this->vcpu.fd, sys_reg_id(3, 3, 13, 0, 2), value);
}

Machine::address_t Machine::entry_address() const noexcept {
	return start_address();
}
Machine::address_t Machine::preserving_entry_address() const noexcept {
	return start_address();
}
Machine::address_t Machine::exit_address() const noexcept {
	return RET_STOP_ADDR;
}

} // namespace tinykvm
