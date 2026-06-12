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

void vCPU::init(int id, Machine& machine, const MachineOptions&)
{
	this->cpu_id = id;
	this->last_fault_address = 0;
	this->m_machine = &machine;

	if (this->fd < 0) {
		this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, this->cpu_id);
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
	}
	if (this->kvm_run == nullptr) {
		kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
			PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
		if (UNLIKELY(kvm_run == MAP_FAILED)) {
			Machine::machine_exception("Failed to create KVM run-time mapped memory");
		}
	}
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
	get_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.pc)), regs.pc);
	get_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.pstate)), regs.pstate);
	const auto sp_reg = ((regs.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL1H)
		? KVM_REG_ARM_CORE_REG(sp_el1)
		: KVM_REG_ARM_CORE_REG(regs.sp);
	get_one_reg(fd, core_reg_id(sp_reg), regs.sp);
	return regs;
}

static void set_arm64_regs(int fd, const tinykvm_arm64regs& regs)
{
	for (size_t i = 0; i < 31; i++) {
		set_one_reg(fd, core_gpr_reg_id(i), regs.regs[i]);
	}
	set_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.pc)), regs.pc);
	set_one_reg(fd, core_reg_id(KVM_REG_ARM_CORE_REG(regs.pstate)), regs.pstate);
	const auto sp_reg = ((regs.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL1H)
		? KVM_REG_ARM_CORE_REG(sp_el1)
		: KVM_REG_ARM_CORE_REG(regs.sp);
	set_one_reg(fd, core_reg_id(sp_reg), regs.sp);
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
		+ sizeof(PerVCPUTable) * this->cpu_id;
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
	if (shared_memory_boundary == 0)
		shared_memory_boundary = UINT64_MAX;

	memory.banks.set_max_pages(max_work_mem / PAGE_SIZE, 0u);
	if (max_work_mem == 0) {
		memory.main_memory_writes = false;
		memory.page_tables = memory.physbase + PT_ADDR;
		foreach_page_makecow(this->memory, kernel_end_address(),
			shared_memory_boundary, split_accessed_hugepages);
		set_one_reg(this->vcpu.fd, sys_reg_id(3, 0, 2, 0, 0), memory.page_tables);
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
