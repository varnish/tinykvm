#include "../machine.hpp"

#include <cerrno>
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
static constexpr uint64_t ARM64_PSTATE_EL1H = 0x5;

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

static tinykvm_arm64regs from_kvm_regs(const struct kvm_regs& src)
{
	tinykvm_arm64regs dst {};
	std::memcpy(dst.regs, src.regs.regs, sizeof(dst.regs));
	dst.pc = src.regs.pc;
	dst.pstate = src.regs.pstate;
	dst.sp = ((dst.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL1H)
		? src.sp_el1
		: src.regs.sp;
	return dst;
}

static struct kvm_regs to_kvm_regs(const tinykvm_arm64regs& src)
{
	struct kvm_regs dst {};
	std::memcpy(dst.regs.regs, src.regs, sizeof(src.regs));
	dst.regs.pc = src.pc;
	dst.regs.pstate = src.pstate;
	if ((src.pstate & ARM64_PSTATE_MODE_MASK) == ARM64_PSTATE_EL1H) {
		dst.sp_el1 = src.sp;
	} else {
		dst.regs.sp = src.sp;
	}
	return dst;
}

const tinykvm_regs& vCPU::registers() const
{
	static thread_local tinykvm_arm64regs regs;
	struct kvm_regs kregs {};
	if (ioctl(this->fd, KVM_GET_REGS, &kregs) < 0) {
		Machine::machine_exception("KVM_GET_REGS failed", errno);
	}
	regs = from_kvm_regs(kregs);
	return regs;
}

tinykvm_regs& vCPU::registers()
{
	static thread_local tinykvm_arm64regs regs;
	struct kvm_regs kregs {};
	if (ioctl(this->fd, KVM_GET_REGS, &kregs) < 0) {
		Machine::machine_exception("KVM_GET_REGS failed", errno);
	}
	regs = from_kvm_regs(kregs);
	return regs;
}

void vCPU::set_registers(const struct tinykvm_regs& regs)
{
	struct kvm_regs kregs = to_kvm_regs(regs);
	if (ioctl(this->fd, KVM_SET_REGS, &kregs) < 0) {
		Machine::machine_exception("KVM_SET_REGS failed", errno);
	}
}

tinykvm_fpuregs vCPU::fpu_registers() const
{
	return {};
}

void vCPU::set_fpu_registers(const struct tinykvm_fpuregs&)
{
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
	this->m_kernel_end = 0;
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	return {0, 0};
}

void Machine::set_tls_base(__u64)
{
	throw MachineException("TLS base setup is not implemented on ARM64");
}

uint64_t vCPU::vcpu_table_addr() const noexcept
{
	return 0;
}

void vCPU::set_vcpu_table_at(unsigned, int)
{
	throw MachineException("Per-vCPU table is not implemented on ARM64");
}

void Machine::prepare_copy_on_write(size_t, uint64_t, bool)
{
	throw MachineException("Copy-on-write is not implemented on ARM64");
}

void Machine::setup_cow_mode(const Machine*)
{
	throw MachineException("Copy-on-write is not implemented on ARM64");
}

void Machine::print_pagetables() const
{
}

void Machine::print_exception_handlers() const
{
}

bool vCPU::is_usermode() const
{
	return false;
}

bool vCPU::is_kernelmode() const
{
	return true;
}

void vCPU::enter_usermode()
{
	throw MachineException("EL0 entry is not implemented on ARM64");
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
	return 0;
}

} // namespace tinykvm
