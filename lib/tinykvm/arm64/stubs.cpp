#include "../machine.hpp"
#include "../linux/threads.hpp"
#include "../smp.hpp"
#include "memory_layout.hpp"
#include <algorithm>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <csignal>
#include <linux/futex.h>
#include <linux/kvm.h>
#include <linux/sched.h>
#include <stdexcept>
#include <sys/ioctl.h>

#define THPRINT(fmt, ...) \
	if (UNLIKELY(cpu.machine().m_verbose_thread_syscalls)) fprintf(stderr, fmt, __VA_ARGS__);

namespace tinykvm {

namespace {

static uint64_t sys_reg_id(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG
		| (((uint64_t)op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK)
		| (((uint64_t)op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK)
		| (((uint64_t)crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK)
		| (((uint64_t)crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK)
		| (((uint64_t)op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK);
}

static uint64_t get_one_reg(int fd, uint64_t id)
{
	uint64_t value = 0;
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)&value,
	};
	if (ioctl(fd, KVM_GET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_GET_ONE_REG failed", errno);
	}
	return value;
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

static uint64_t core_reg_id(uint64_t reg)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | reg;
}
/* SPSR_EL1 holds the EL0 PSTATE banked on exception entry; the user's PC and
   SP are likewise banked in ELR_EL1 / SP_EL0 (read via tinykvm_regs at EL1h).
   TPIDR_EL1 is where the EL1 sync-vector stub stashes the user's x9 before
   using it as scratch, so it carries the real x9 at a syscall trap. */
static const uint64_t SPSR_EL1_ID   = core_reg_id(KVM_REG_ARM_CORE_REG(spsr[KVM_SPSR_EL1]));
static const uint64_t TPIDR_EL1_ID  = sys_reg_id(3, 0, 13, 0, 4);

/* Per-thread key for signal bookkeeping. Single-threaded guests never create
   a MultiThreading object, so fall back to slot 0 (matching sigaltstack). */
static int current_sig_tid(vCPU& cpu)
{
	return cpu.machine().has_threads() ? cpu.machine().threads().gettid() : 0;
}

/* Shared body of kill/tkill/tgkill: deliver `sig` to a registered handler,
   drop it if ignored, or apply the kernel's default disposition. When a
   handler is entered the trap frame is rewritten to run it at EL0 and the
   call does not "return" here -- the rt_sigreturn trampoline resumes the
   guest after the originating syscall. */
static void deliver_signal_or_default(vCPU& cpu, int sig)
{
	auto& regs = cpu.registers();
	if (sig == 0) { // existence probe
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}
	constexpr uint64_t IGNORE_HANDLER = 1; // SIG_IGN
	if (sig > 0 && sig <= 64) {
		auto& sigact = cpu.machine().sigaction(sig);
		if (!sigact.is_unset() && sigact.handler != IGNORE_HANDLER) {
			cpu.machine().signals().enter(cpu, sig);
			return;
		}
		if (sigact.handler == IGNORE_HANDLER) {
			regs.sysret() = 0;
			cpu.set_registers(regs);
			return;
		}
	}
	/* No handler: match the kernel's default dispositions -- a few signals are
	   ignored by default, everything else terminates the VM. The exit status
	   follows the shell convention 128+sig (Machine::return_value()). */
	switch (sig) {
	case SIGCHLD:
	case SIGCONT:
	case SIGURG:
	case SIGWINCH:
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}
	regs.sysret() = 128 + sig;
	cpu.set_registers(regs);
	cpu.stop();
}

/* Guest-visible signal frame, laid out to match the arm64 kernel uapi so that
   SA_SIGINFO handlers receive valid siginfo/ucontext pointers. rt_sigreturn
   restores the interrupted context from a host-side snapshot rather than from
   these bytes, so the machine context below is informational (handler edits to
   uc_mcontext are not honored on return). */
/* Field names are prefixed to dodge glibc's si_signo/si_code/si_pid/... and
   errno macros from <signal.h>, which would otherwise expand inside here. */
struct GuestSiginfo {        // kernel siginfo_t
	int32_t  ksi_signo;  // 0
	int32_t  ksi_errno;  // 4
	int32_t  ksi_code;   // 8
	int32_t  _pad0;      // 12
	int32_t  ksi_pid;    // 16  (_sifields._kill._pid)
	int32_t  ksi_uid;    // 20  (_sifields._kill._uid)
	uint8_t  _rest[128 - 24];
};
static_assert(sizeof(GuestSiginfo) == 128, "siginfo_t is 128 bytes");

struct GuestSigcontext {     // arm64 uapi struct sigcontext
	uint64_t fault_address;  // 0
	uint64_t regs[31];       // 8
	uint64_t sp;             // 256
	uint64_t pc;             // 264
	uint64_t pstate;         // 272
	alignas(16) uint8_t __reserved[4096]; // 288
};
static_assert(offsetof(GuestSigcontext, regs) == 8);
static_assert(offsetof(GuestSigcontext, sp) == 256);
static_assert(offsetof(GuestSigcontext, pc) == 264);
static_assert(offsetof(GuestSigcontext, pstate) == 272);
static_assert(offsetof(GuestSigcontext, __reserved) == 288);

struct GuestUcontext {       // arm64 uapi struct ucontext (sigmask before mcontext)
	uint64_t uc_flags;       // 0
	uint64_t uc_link;        // 8
	uint64_t ss_sp;          // 16  uc_stack.ss_sp
	int32_t  ss_flags;       // 24  uc_stack.ss_flags
	int32_t  _pad0;          // 28
	uint64_t ss_size;        // 32  uc_stack.ss_size
	uint8_t  uc_sigmask[128];// 40  sigset_t padded to 1024 bits
	uint8_t  _pad1[8];       // 168 -> align uc_mcontext to 16
	GuestSigcontext uc_mcontext; // 176
};
static_assert(offsetof(GuestUcontext, uc_mcontext) == 176);

struct GuestRtSigframe {
	GuestSiginfo  info; // 0
	GuestUcontext uc;   // 128
};
static_assert(offsetof(GuestRtSigframe, uc) == 128);

struct Arm64SnapshotSysregs {
	uint64_t mair_el1;
	uint64_t tcr_el1;
	uint64_t ttbr0_el1;
	uint64_t sctlr_el1;
	uint64_t cpacr_el1;
	uint64_t vbar_el1;
	uint64_t tpidr_el0;
};

static Arm64SnapshotSysregs get_arm64_snapshot_sysregs(const vCPU& cpu)
{
	return {
		get_one_reg(cpu.fd, sys_reg_id(3, 0, 10, 2, 0)),
		get_one_reg(cpu.fd, sys_reg_id(3, 0, 2, 0, 2)),
		get_one_reg(cpu.fd, sys_reg_id(3, 0, 2, 0, 0)),
		get_one_reg(cpu.fd, sys_reg_id(3, 0, 1, 0, 0)),
		get_one_reg(cpu.fd, sys_reg_id(3, 0, 1, 0, 2)),
		get_one_reg(cpu.fd, sys_reg_id(3, 0, 12, 0, 0)),
		get_one_reg(cpu.fd, sys_reg_id(3, 3, 13, 0, 2)),
	};
}

static void set_arm64_snapshot_sysregs(vCPU& cpu, const Arm64SnapshotSysregs& regs)
{
	set_one_reg(cpu.fd, sys_reg_id(3, 0, 10, 2, 0), regs.mair_el1);
	set_one_reg(cpu.fd, sys_reg_id(3, 0, 2, 0, 2), regs.tcr_el1);
	set_one_reg(cpu.fd, sys_reg_id(3, 0, 2, 0, 0), regs.ttbr0_el1);
	set_one_reg(cpu.fd, sys_reg_id(3, 0, 1, 0, 0), regs.sctlr_el1);
	set_one_reg(cpu.fd, sys_reg_id(3, 0, 1, 0, 2), regs.cpacr_el1);
	set_one_reg(cpu.fd, sys_reg_id(3, 0, 12, 0, 0), regs.vbar_el1);
	set_one_reg(cpu.fd, sys_reg_id(3, 3, 13, 0, 2), regs.tpidr_el0);
}

struct Arm64SnapshotState {
	static constexpr uint32_t MAGIC = 0x41344B54; // 'TK4A'
	static constexpr uint32_t VERSION = 1;

	uint32_t magic;
	uint32_t version;
	uint32_t size;
	uint32_t reserved;

	tinykvm_arm64regs regs;
	tinykvm_arm64fpuregs fpu;
	Arm64SnapshotSysregs sysregs;

	bool m_prepped;
	bool m_forked;
	bool m_just_reset;
	bool m_relocate_fixed_mmap;

	Machine::address_t m_image_base;
	Machine::address_t m_stack_address;
	Machine::address_t m_heap_address;
	Machine::address_t m_brk_address;
	Machine::address_t m_brk_end_address;
	Machine::address_t m_start_address;
	Machine::address_t m_kernel_end;
	Machine::address_t mmap_current;
	Machine::address_t m_page_tables;
	bool main_memory_writes;

	char current[0];

	static constexpr size_t Size() noexcept { return vMemory::ColdStartStateSize(); }
};

} // namespace

bool Machine::load_snapshot_state()
{
	if (!memory.has_loadable_snapshot_state()) {
		return false;
	}
	if (!this->memory.has_snapshot_area()) {
		throw std::runtime_error("No snapshot state area allocated");
	}
	if (this->is_forked()) {
		throw std::runtime_error("Cannot load snapshot state into a forked VM");
	}

	auto& state = *reinterpret_cast<Arm64SnapshotState*>(
		this->memory.get_snapshot_state_area());
	if (state.magic != Arm64SnapshotState::MAGIC) {
		throw std::runtime_error("No valid ARM64 snapshot state found");
	}
	if (state.version != Arm64SnapshotState::VERSION
		|| state.size < sizeof(Arm64SnapshotState)
		|| state.size > Arm64SnapshotState::Size()) {
		throw std::runtime_error("Invalid ARM64 snapshot state");
	}

	try {
		this->set_registers(state.regs);
		this->set_fpu_registers(state.fpu);
		set_arm64_snapshot_sysregs(this->vcpu, state.sysregs);
		this->m_prepped = state.m_prepped;
		this->m_forked = state.m_forked;
		this->m_just_reset = state.m_just_reset;
		this->m_relocate_fixed_mmap = state.m_relocate_fixed_mmap;
		this->m_image_base = state.m_image_base;
		this->m_stack_address = state.m_stack_address;
		this->m_heap_address = state.m_heap_address;
		this->m_brk_address = state.m_brk_address;
		this->m_brk_end_address = state.m_brk_end_address;
		this->m_start_address = state.m_start_address;
		this->m_kernel_end = state.m_kernel_end;
		this->m_mmap_cache.current() = state.mmap_current;
		this->memory.page_tables = state.m_page_tables;
		this->memory.main_memory_writes = state.main_memory_writes;
	} catch (const MachineException&) {
		return false;
	}
	return true;
}

bool vMemory::has_loadable_snapshot_state() const noexcept
{
	if (!this->has_snapshot_area()) {
		return false;
	}
	const auto* state = reinterpret_cast<const Arm64SnapshotState*>(
		this->get_snapshot_state_area());
	return state->magic == Arm64SnapshotState::MAGIC;
}

void* vMemory::get_snapshot_state_area() const
{
	if (!this->has_snapshot_area()) {
		throw std::runtime_error("No snapshot state area allocated");
	}
	return this->ptr + this->size;
}

void Machine::save_snapshot_state_now(const std::vector<std::pair<uint64_t, uint64_t>>&) const
{
	if (this->is_forked()) {
		throw std::runtime_error("Cannot save snapshot state of a forked VM");
	}
	auto& state = *reinterpret_cast<Arm64SnapshotState*>(
		this->memory.get_snapshot_state_area());
	try {
		state.magic = Arm64SnapshotState::MAGIC;
		state.version = Arm64SnapshotState::VERSION;
		state.size = sizeof(Arm64SnapshotState);
		state.reserved = 0;
		state.regs = this->registers();
		state.fpu = this->fpu_registers();
		state.sysregs = get_arm64_snapshot_sysregs(this->vcpu);
		state.m_prepped = this->m_prepped;
		state.m_forked = this->m_forked;
		state.m_just_reset = this->m_just_reset;
		state.m_relocate_fixed_mmap = this->m_relocate_fixed_mmap;
		state.m_image_base = this->m_image_base;
		state.m_stack_address = this->m_stack_address;
		state.m_heap_address = this->m_heap_address;
		state.m_brk_address = this->m_brk_address;
		state.m_brk_end_address = this->m_brk_end_address;
		state.m_start_address = this->m_start_address;
		state.m_kernel_end = this->m_kernel_end;
		state.mmap_current = this->m_mmap_cache.current();
		state.m_page_tables = this->memory.page_tables;
		state.main_memory_writes = this->memory.main_memory_writes;
	} catch (...) {
		state.magic = 0;
		throw;
	}
}

void* Machine::get_snapshot_state_user_area() const
{
	if (!this->memory.has_snapshot_area()) {
		return nullptr;
	}
	auto& state = *reinterpret_cast<Arm64SnapshotState*>(
		this->memory.get_snapshot_state_area());
	if (state.magic != Arm64SnapshotState::MAGIC
		|| state.version != Arm64SnapshotState::VERSION
		|| state.size < sizeof(Arm64SnapshotState)
		|| state.size > Arm64SnapshotState::Size()) {
		return nullptr;
	}
	return reinterpret_cast<char*>(&state) + state.size;
}

Machine& Machine::remote()
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

const Machine& Machine::remote() const
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::permanent_remote_connect(Machine&)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::remote_update_gigapage_mappings(Machine&, bool)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::remote_connect(Machine&, bool)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::ipre_remote_resume_now(bool, std::function<void(Machine&)>)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::ipre_permanent_remote_resume_now(bool)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::remote_pfault_permanent_ipre(uint64_t, uint64_t)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

Machine::address_t Machine::remote_activate_now()
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

Machine::address_t Machine::remote_disconnect()
{
	return 0;
}

bool Machine::is_remote_connected() const noexcept
{
	return false;
}

bool Machine::is_foreign_address(address_t) const noexcept
{
	return false;
}

SMP& Machine::smp()
{
	throw MachineException("SMP is not implemented on ARM64");
}

const SMP& Machine::smp() const
{
	throw MachineException("SMP is not implemented on ARM64");
}

bool Machine::smp_active() const noexcept
{
	return false;
}

int Machine::smp_active_count() const noexcept
{
	return 0;
}

void Machine::smp_wait()
{
}

void Machine::smp_vcpu_broadcast(std::function<void(vCPU&)>)
{
}

SMP::~SMP() = default;

SMP::MPvCPU::MPvCPU(int, Machine&)
	: thpool(0, 0, false)
{
	throw MachineException("SMP is not implemented on ARM64");
}

SMP::MPvCPU::~MPvCPU() = default;

void SMP::MPvCPU::blocking_message(std::function<void(vCPU&)>)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::MPvCPU::async_exec(MPvCPU_data&)
{
	throw MachineException("SMP is not implemented on ARM64");
}

SMP::MPvCPU_data* SMP::smp_allocate_vcpu_data(size_t)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::prepare_cpus(size_t)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::broadcast(std::function<void(vCPU&)>)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::timed_smpcall_array(size_t, address_t, uint32_t, address_t, float, address_t, uint32_t)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::timed_smpcall_clone(size_t, address_t, uint32_t, float, const tinykvm_regs&)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::wait()
{
}

std::vector<long> SMP::gather_return_values(unsigned)
{
	return {};
}

Thread::Thread(MultiThreading& mtr, int t, uint64_t tls, uint64_t stack)
	: mt(mtr), tid(t)
{
	this->fsbase = tls;
	this->clear_tid = 0;
	this->stored_regs.stackptr() = stack;
}

Thread::Thread(MultiThreading& mtr, const Thread& other)
	: mt(mtr), tid(other.tid), stored_regs(other.stored_regs),
	  fsbase(other.fsbase), clear_tid(other.clear_tid),
	  futex_addr(other.futex_addr)
{
}

void Thread::suspend(uint64_t return_value)
{
	this->stored_regs = mt.machine.registers();
	this->stored_regs.sysret() = return_value;
	this->fsbase = mt.machine.get_fsgs().first;
	mt.m_suspended.push_back(this);
}

tinykvm_regs Thread::activate()
{
	mt.m_current = this;
	mt.machine.set_tls_base(this->fsbase);
	auto regs = mt.machine.registers();
	regs.stackptr() = this->stored_regs.stackptr();
	return regs;
}

void Thread::resume()
{
	mt.m_current = this;
	mt.machine.set_registers(this->stored_regs);
	mt.machine.set_tls_base(this->fsbase);
}

void Thread::exit()
{
	const bool exiting_myself = (mt.get_thread().tid == this->tid);
	if (this->clear_tid) {
		// CLONE_CHILD_CLEARTID: zero the userspace TID and wake any joiner
		// blocked on it (pthread_join FUTEX_WAITs on this same address).
		const uint32_t value = 0;
		mt.machine.copy_to_guest(this->clear_tid, &value, sizeof(value));
		mt.wake_futex(this->clear_tid, SIZE_MAX);
	}
	auto& thr = this->mt;
	thr.erase_thread(this->tid);
	if (exiting_myself) {
		thr.wakeup_next();
	}
}

MultiThreading::MultiThreading(Machine& m) : machine(m)
{
	auto it = m_threads.try_emplace(1, *this, 1, 0x0, 0x0);
	m_current = &it.first->second;
}

void MultiThreading::reset_to(const MultiThreading& other)
{
	if (other.m_current != nullptr) {
		this->machine.set_tls_base(other.m_current->fsbase);
	}
	m_threads.clear();
	m_suspended.clear();
	for (const auto& it : other.m_threads) {
		m_threads.try_emplace(it.first, *this, it.second);
	}
	for (const auto* t : other.m_suspended) {
		m_suspended.push_back(get_thread(t->tid));
	}
	m_current = other.m_current != nullptr ? get_thread(other.m_current->tid) : nullptr;
	thread_counter = other.thread_counter;
}

void MultiThreading::set_to_and_suspend_others(int tid)
{
	this->m_suspended.clear();
	for (auto& [otid, thread] : m_threads) {
		// Forcing a thread set establishes a fresh schedule: every thread is
		// runnable (a thread restored from a snapshot while futex-blocked
		// re-checks its predicate on resume and blocks again cleanly). This
		// also upholds the invariant that the current thread is never marked
		// futex-blocked.
		thread.futex_addr = 0;
		if (otid != tid) {
			m_suspended.push_back(&thread);
		}
	}
	this->m_current = get_thread(tid);
}

Thread& MultiThreading::get_thread()
{
	return *m_current;
}

Thread* MultiThreading::get_thread(int tid)
{
	auto it = m_threads.find(tid);
	if (it == m_threads.end())
		return nullptr;
	return &it->second;
}

Thread& MultiThreading::create(int tid)
{
	auto it = m_threads.try_emplace(tid, *this, tid, 0, 0);
	return it.first->second;
}

Thread& MultiThreading::create(int flags, uint64_t ctid, uint64_t ptid,
	uint64_t stack, uint64_t tls)
{
	const int tid = ++this->thread_counter;
	auto it = m_threads.try_emplace(tid, *this, tid, tls, stack);
	Thread& thread = it.first->second;

	if (flags & CLONE_CHILD_SETTID) {
		machine.copy_to_guest(ctid, &tid, sizeof(tid));
	}
	if (flags & CLONE_PARENT_SETTID) {
		machine.copy_to_guest(ptid, &tid, sizeof(tid));
	}
	if (flags & CLONE_CHILD_CLEARTID) {
		thread.clear_tid = ctid;
	}
	return thread;
}

Thread* MultiThreading::next_runnable()
{
	// Peek the first runnable (non-futex-blocked) thread in FIFO order without
	// removing it; switch_to/wakeup_next remove it once committed.
	for (auto* t : m_suspended) {
		if (t->futex_addr == 0)
			return t;
	}
	return nullptr;
}

void MultiThreading::switch_to(Thread* next, int64_t result, uint64_t block_addr)
{
	// Suspend the current thread (blocked on block_addr, or runnable when 0)
	// and resume `next`, which must already be in the suspended set. Suspending
	// before removing `next` keeps the scheduler consistent if push_back throws.
	auto& thread = get_thread();
	thread.suspend(result);
	thread.futex_addr = block_addr;
	auto it = std::find(m_suspended.begin(), m_suspended.end(), next);
	assert(it != m_suspended.end());
	m_suspended.erase(it);
	next->resume();
}

bool MultiThreading::suspend_and_yield(int64_t result, uint64_t block_addr)
{
	Thread* next = next_runnable();
	if (next == nullptr) {
		// No other runnable thread to switch to.
		return false;
	}
	switch_to(next, result, block_addr);
	return true;
}

std::pair<size_t, Thread*> MultiThreading::wake_futex(uint64_t addr, size_t max_count)
{
	size_t woken = 0;
	Thread* first = nullptr;
	if (addr == 0)
		return {0, nullptr};
	for (auto* t : m_suspended) {
		if (woken >= max_count)
			break;
		if (t->futex_addr == addr) {
			t->futex_addr = 0; // now runnable
			if (first == nullptr)
				first = t;
			woken += 1;
		}
	}
	return {woken, first};
}

void MultiThreading::erase_thread(int tid)
{
	auto it = m_threads.find(tid);
	assert(it != m_threads.end());
	m_threads.erase(it);
}

void MultiThreading::wakeup_next()
{
	assert(!m_suspended.empty());
	Thread* next = next_runnable();
	if (next != nullptr) {
		auto it = std::find(m_suspended.begin(), m_suspended.end(), next);
		m_suspended.erase(it);
	} else {
		// Every suspended thread is futex-blocked (e.g. a missed wake). Rather
		// than hang, force-run the front thread; it will re-check its condition
		// and, if still unsatisfied, hit the FUTEX_WAIT deadlock fallback.
		next = m_suspended.front();
		next->futex_addr = 0;
		m_suspended.erase(m_suspended.begin());
	}
	next->resume();
}

const MultiThreading& Machine::threads() const
{
	if (UNLIKELY(!m_mt)) {
		m_mt.reset(new MultiThreading(*const_cast<Machine*>(this)));
	}
	return *m_mt;
}

MultiThreading& Machine::threads()
{
	if (UNLIKELY(!m_mt)) {
		m_mt.reset(new MultiThreading(*this));
	}
	return *m_mt;
}

void Machine::setup_multithreading()
{
	Machine::install_syscall_handler(
		124, [] (vCPU& cpu) { // sched_yield
			THPRINT("sched_yield on tid=%d\n",
				cpu.machine().threads().get_thread().tid);
			cpu.machine().threads().suspend_and_yield();
		});
	Machine::install_syscall_handler(
		220, [] (vCPU& cpu) { // clone
			auto& regs = cpu.registers();
			const auto flags = regs.sysarg(0);
			auto stack = regs.sysarg(1);
			const auto ptid = regs.sysarg(2);
			uint64_t tls = regs.sysarg(3);
			const auto ctid = regs.sysarg(4);
			if (stack == 0x0) {
				static constexpr size_t STACK_SIZE = 0x200000;
				stack = cpu.machine().mmap_allocate(STACK_SIZE) + STACK_SIZE;
			}
			if ((flags & CLONE_SETTLS) == 0) {
				tls = cpu.machine().get_fsgs().first;
			}
			auto& parent = cpu.machine().threads().get_thread();
			auto& thread = cpu.machine().threads().create(flags, ctid, ptid, stack, tls);
			THPRINT(">>> clone(stack=0x%llX, flags=%llX,"
					" parent=%d, ctid=0x%llX ptid=0x%llX, tls=0x%lX) = %d\n",
					stack, flags, parent.tid, ctid, ptid, tls, thread.tid);
			parent.suspend(thread.tid);
			regs = thread.activate();
			regs.sysret() = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		435, [] (vCPU& cpu) { // clone3
			auto& regs = cpu.registers();
			static constexpr uint32_t SETTLS = 0x00080000;
			struct clone3_args {
				uint64_t flags;
				uint64_t pidfd;
				uint64_t child_tid;
				uint64_t parent_tid;
				uint64_t exit_signal;
				uint64_t stack;
				uint64_t stack_size;
				uint64_t tls;
				uint64_t set_tid_array;
				uint64_t set_tid_count;
				uint64_t cgroup;
			} args;
			if (regs.sysarg(1) < sizeof(clone3_args)) {
				regs.sysret() = -ENOSPC;
				cpu.set_registers(regs);
				return;
			}
			cpu.machine().copy_from_guest(&args, regs.sysarg(0), sizeof(args));
			auto stack = args.stack + args.stack_size;
			if (stack == 0x0) {
				static constexpr size_t STACK_SIZE = 0x200000;
				stack = cpu.machine().mmap_allocate(STACK_SIZE) + STACK_SIZE;
			}
			auto tls = args.tls;
			if ((args.flags & SETTLS) == 0) {
				tls = cpu.machine().get_fsgs().first;
			}
			auto& parent = cpu.machine().threads().get_thread();
			auto& thread = cpu.machine().threads().create(
				args.flags, args.child_tid, args.parent_tid, stack, tls);
			THPRINT(">>> clone3(stack=0x%lX, flags=%lX,"
					" parent=%d, ctid=0x%lX ptid=0x%lX, tls=0x%lX) = %d\n",
					stack, args.flags, parent.tid, args.child_tid,
					args.parent_tid, tls, thread.tid);
			if (args.set_tid_count > 0) {
				uint64_t set_tid = 0;
				cpu.machine().copy_from_guest(&set_tid, args.set_tid_array, sizeof(set_tid));
				thread.clear_tid = set_tid;
			}
			parent.suspend(thread.tid);
			regs = thread.activate();
			regs.sysret() = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		93, [] (vCPU& cpu) { // exit
			if (cpu.machine().has_threads()) {
				auto& thread = cpu.machine().threads().get_thread();
				THPRINT(">>> Exit on tid=%d\n", thread.tid);
				if (thread.tid != 1) {
					thread.exit();
					return;
				}
			}
			cpu.stop();
		});
	Machine::install_syscall_handler(94, Machine::get_syscall_handler(93)); // exit_group
	Machine::install_syscall_handler(
		178, [] (vCPU& cpu) { // gettid
			auto& regs = cpu.registers();
			regs.sysret() = cpu.machine().has_threads()
				? cpu.machine().threads().get_thread().tid : 1;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		98, [] (vCPU& cpu) { // futex
			auto& regs = cpu.registers();
			const auto addr = regs.sysarg(0);
			const auto futex_op = regs.sysarg(1);
			const uint32_t val = regs.sysarg(2);
			if ((futex_op & 0xF) == FUTEX_WAIT || (futex_op & 0xF) == FUTEX_WAIT_BITSET) {
				uint32_t futexVal = 0;
				cpu.machine().copy_from_guest(&futexVal, addr, sizeof(futexVal));
				if (futexVal == val) {
					// Block this thread on `addr` and run a runnable thread; it
					// resumes (returning 0) when a FUTEX_WAKE targets `addr`.
					if (cpu.machine().threads().suspend_and_yield(0, addr)) {
						return;
					}
					// No other runnable thread: force progress to avoid a hang.
					futexVal = 0;
					cpu.machine().copy_to_guest(addr, &futexVal, sizeof(futexVal));
				}
				regs.sysret() = 0;
			} else if ((futex_op & 0xF) == FUTEX_WAKE || (futex_op & 0xF) == FUTEX_WAKE_BITSET) {
				// Mark up to `val` threads blocked on this address as runnable,
				// then hand control to the FIRST one woken. The cooperative
				// scheduler never preempts, so a waker that did not yield could
				// run to completion before a signalled waiter ever runs — a
				// lost-wakeup deadlock for flag-based condvar handshakes. The
				// waker stays runnable and resumes (returning the woken count)
				// after the woken thread blocks again.
				const auto [woken, first] = cpu.machine().threads().wake_futex(addr, val);
				if (first != nullptr) {
					cpu.machine().threads().switch_to(first, woken);
					return;
				}
				regs.sysret() = woken; // woken == 0: nothing was waiting
			} else {
				throw std::runtime_error("Unimplemented futex op: " + std::to_string(futex_op & 0xF));
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		96, [] (vCPU& cpu) { // set_tid_address
			auto& regs = cpu.registers();
			auto& thread = cpu.machine().threads().get_thread();
			thread.clear_tid = regs.sysarg(0);
			regs.sysret() = thread.tid;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		129, [] (vCPU& cpu) { // kill(pid, sig)
			deliver_signal_or_default(cpu, cpu.registers().sysarg(1));
		});
	Machine::install_syscall_handler(
		130, [] (vCPU& cpu) { // tkill(tid, sig)
			deliver_signal_or_default(cpu, cpu.registers().sysarg(1));
		});
	Machine::install_syscall_handler(
		131, [] (vCPU& cpu) { // tgkill(tgid, tid, sig)
			deliver_signal_or_default(cpu, cpu.registers().sysarg(2));
		});
	Machine::install_syscall_handler(
		139, [] (vCPU& cpu) { // rt_sigreturn
			/* Restore the context saved by Signals::enter. Pop the current
			   thread's signal snapshot and write it back into the EL1h trap
			   frame: the GP regs and (banked) user PC/SP go through
			   tinykvm_regs, while SPSR_EL1 and the FP/SIMD state are restored
			   directly. The vector eret then returns to the interrupted EL0
			   instruction. */
			auto& signals = cpu.machine().signals();
			auto& pt = signals.per_thread(current_sig_tid(cpu));
			if (pt.saved.empty()) {
				throw MachineException("rt_sigreturn with no saved signal context");
			}
			const SavedSignalContext saved = pt.saved.back();
			pt.saved.pop_back();

			auto regs = cpu.registers(); // EL1h frame; keep core pstate = EL1h
			for (size_t i = 0; i < 31; i++)
				regs.regs[i] = saved.regs.regs[i];
			regs.pc = saved.regs.pc; // -> ELR_EL1
			regs.sp = saved.regs.sp; // -> SP_EL0
			cpu.set_registers(regs);
			set_one_reg(cpu.fd, SPSR_EL1_ID, saved.regs.pstate);
			/* The sync-vector stub reloads x9 from TPIDR_EL1 on its way out
			   (eret), so the core x9 just set would be discarded -- stage the
			   user's x9 where the stub will pick it up. */
			set_one_reg(cpu.fd, TPIDR_EL1_ID, saved.regs.regs[9]);
			cpu.set_fpu_registers(saved.fpu);
		});
}

Signals::Signals() = default;
Signals::~Signals() = default;

SignalAction& Signals::get(int sig)
{
	if (sig > 0)
		return signals.at(sig - 1);
	throw MachineException("Signal 0 invoked", sig);
}

void Signals::enter(vCPU& cpu, int sig)
{
	if (sig <= 0 || sig > 64)
		return;
	auto& sigact = signals.at(sig - 1);

	const int tid = current_sig_tid(cpu);
	auto& pt = this->per_thread(tid);

	/* Snapshot the interrupted EL0 context for rt_sigreturn. At a syscall trap
	   the vCPU is parked at EL1h, where tinykvm_regs reports pc=ELR_EL1 (the
	   user's resume address) and sp=SP_EL0 (the user stack); x0..x30 hold the
	   user's values except x9, which the vector stub banked into TPIDR_EL1.
	   Recover the real x9 and the user PSTATE from SPSR_EL1. */
	SavedSignalContext saved;
	saved.regs = cpu.registers();
	saved.regs.regs[9] = get_one_reg(cpu.fd, TPIDR_EL1_ID);
	saved.regs.pstate  = get_one_reg(cpu.fd, SPSR_EL1_ID);
	saved.fpu = cpu.fpu_registers();
	pt.saved.push_back(saved);

	/* Run the handler on the alternate stack if it asked for one (SA_ONSTACK),
	   otherwise continue down the user's current stack. */
	uint64_t sp = saved.regs.sp;
	const bool on_altstack = sigact.altstack && pt.stack.ss_sp != 0x0;
	if (on_altstack)
		sp = pt.stack.ss_sp + pt.stack.ss_size;

	/* Reserve and 16-align the signal frame below the chosen stack pointer. */
	const uint64_t frame_addr = (sp - sizeof(GuestRtSigframe)) & ~uint64_t(15);

	GuestRtSigframe frame {};
	frame.info.ksi_signo = sig;
	frame.info.ksi_code  = 0; // SI_USER
	frame.info.ksi_pid   = (tid != 0) ? tid : 1;
	if (on_altstack) {
		frame.uc.ss_sp    = pt.stack.ss_sp;
		frame.uc.ss_flags = pt.stack.ss_flags;
		frame.uc.ss_size  = pt.stack.ss_size;
	}
	for (size_t i = 0; i < 31; i++)
		frame.uc.uc_mcontext.regs[i] = saved.regs.regs[i];
	frame.uc.uc_mcontext.sp     = saved.regs.sp;
	frame.uc.uc_mcontext.pc     = saved.regs.pc;
	frame.uc.uc_mcontext.pstate = saved.regs.pstate;
	cpu.machine().copy_to_guest(frame_addr, &frame, sizeof(frame));

	/* Enter the handler at EL0. registers() is still the EL1h trap frame, so
	   writing pc/sp routes to ELR_EL1/SP_EL0 and the vector eret lands in the
	   handler with the user's (EL0t) SPSR. The link register points at the
	   rt_sigreturn trampoline so a returning handler resumes the guest. */
	auto regs = cpu.registers();
	regs.regs[0]  = sig;                                          // signo
	regs.regs[1]  = frame_addr + offsetof(GuestRtSigframe, info); // siginfo*
	regs.regs[2]  = frame_addr + offsetof(GuestRtSigframe, uc);   // ucontext*
	regs.regs[30] = SIGRETURN_TRAMPOLINE_ADDR;                    // lr
	regs.sp = frame_addr;
	regs.pc = sigact.handler;
	cpu.set_registers(regs);
}

SignalAction& Machine::sigaction(int sig)
{
	return signals().get(sig);
}

void Machine::print_remote_gdb_backtrace(const std::string&, const RemoteGDBOptions&)
{
	throw MachineException("Remote GDB support is not implemented on ARM64");
}

} // namespace tinykvm
