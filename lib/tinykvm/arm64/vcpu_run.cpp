#include "../machine.hpp"

#include "memory_layout.hpp"
#include "../util/scoped_profiler.hpp"
#include <cerrno>
#include <linux/kvm.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <time.h>

extern "C" int gettid();
#define PRINTER(printer, buffer, fmt, ...) \
	printer(buffer, \
		snprintf(buffer, sizeof(buffer), \
		fmt, ##__VA_ARGS__));

namespace tinykvm {
	thread_local bool timer_was_triggered = false;
}

extern "C"
void tinykvm_timer_signal_handler(int sig) {
	if (sig == SIGUSR2) {
		tinykvm::timer_was_triggered = true;
	}
}

namespace tinykvm {
static constexpr bool VERBOSE_TIMER = false;

static uint64_t sys_reg_id(unsigned op0, unsigned op1, unsigned crn, unsigned crm, unsigned op2)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM64_SYSREG
		| (((uint64_t)op0 << KVM_REG_ARM64_SYSREG_OP0_SHIFT) & KVM_REG_ARM64_SYSREG_OP0_MASK)
		| (((uint64_t)op1 << KVM_REG_ARM64_SYSREG_OP1_SHIFT) & KVM_REG_ARM64_SYSREG_OP1_MASK)
		| (((uint64_t)crn << KVM_REG_ARM64_SYSREG_CRN_SHIFT) & KVM_REG_ARM64_SYSREG_CRN_MASK)
		| (((uint64_t)crm << KVM_REG_ARM64_SYSREG_CRM_SHIFT) & KVM_REG_ARM64_SYSREG_CRM_MASK)
		| (((uint64_t)op2 << KVM_REG_ARM64_SYSREG_OP2_SHIFT) & KVM_REG_ARM64_SYSREG_OP2_MASK);
}

static uint64_t get_sysreg(int fd, uint64_t id)
{
	uint64_t value = 0;
	struct kvm_one_reg reg {
		.id = id,
		.addr = (uint64_t)&value,
	};
	if (ioctl(fd, KVM_GET_ONE_REG, &reg) < 0) {
		throw MachineException("KVM_GET_ONE_REG sysreg failed", errno);
	}
	return value;
}

static bool handle_cow_data_abort(vCPU& cpu)
{
	const uint64_t ESR_EL1 = sys_reg_id(3, 0, 5, 2, 0);
	const uint64_t FAR_EL1 = sys_reg_id(3, 0, 6, 0, 0);
	const uint64_t esr = get_sysreg(cpu.fd, ESR_EL1);
	const uint8_t ec = esr >> 26;
	if (ec != 0x24 && ec != 0x25) {
		return false;
	}

	const uint32_t iss = esr & 0x01FFFFFFu;
	const uint32_t dfsc = iss & 0x3Fu;
	const bool write = (iss & (1u << 6)) != 0;
	if (!write || dfsc < 0x0D || dfsc > 0x0F) {
		return false;
	}

	const uint64_t far = get_sysreg(cpu.fd, FAR_EL1);
	ScopedProfiler<MachineProfiling::PageFault> prof(cpu.machine().profiling());
	cpu.machine().main_memory().get_writable_page(far & ~PageMask(), 1ULL, false, true);
	cpu.last_fault_address = far;
	return true;
}

bool vCPU::timed_out() const
{
	if (timer_was_triggered) {
		timer_was_triggered = false;
		return true;
	}
	return false;
}

void vCPU::run(uint32_t ticks)
{
	timer_was_triggered = false;
	this->timer_ticks = ticks;
	if (timer_ticks != 0) {
		const struct itimerspec its {
			.it_interval = {
				.tv_sec = 0, .tv_nsec = 20'000'000L
			},
			.it_value = {
				.tv_sec = ticks / 1000,
				.tv_nsec = (ticks % 1000) * 1000000L
			}
		};
		timer_settime((timer_t)this->timer_id, 0, &its, nullptr);
		if constexpr (VERBOSE_TIMER) {
			printf("Timer %p enabled\n", timer_id);
		}
	}

	try {
		this->stopped = false;
		while(run_once());
	} catch (...) {
		disable_timer();
		throw;
	}

	disable_timer();
}

void vCPU::disable_timer()
{
	timer_was_triggered = false;
	if (timer_ticks != 0) {
		this->timer_ticks = 0;
		struct itimerspec its;
		__builtin_memset(&its, 0, sizeof(its));
		timer_settime((timer_t)this->timer_id, 0, &its, nullptr);
	}
}

long vCPU::run_once()
{
	int result;
	{
		ScopedProfiler<MachineProfiling::VCpuRun> prof(machine().profiling());
		this->flush_registers();
		result = ioctl(this->fd, KVM_RUN, 0);
		this->invalidate_register_cache();
	}
	if (UNLIKELY(result < 0)) {
		if (this->timer_ticks) {
			Machine::timeout_exception("Timeout Exception", this->timer_ticks);
		} else if (errno == EINTR) {
			Machine::timeout_exception("Interrupted (signal)", 0);
		}
		Machine::machine_exception("KVM_RUN failed (errno)", errno);
	}
	if (this->timer_ticks && UNLIKELY(timer_was_triggered)) {
		Machine::timeout_exception("Timeout Exception", this->timer_ticks);
	}

	switch (kvm_run->exit_reason) {
	case KVM_EXIT_DEBUG:
		return KVM_EXIT_DEBUG;
	case KVM_EXIT_HLT:
	case KVM_EXIT_SHUTDOWN:
	case KVM_EXIT_SYSTEM_EVENT:
		this->stopped = true;
		return 0;
	case KVM_EXIT_MMIO:
		if (kvm_run->mmio.phys_addr == ARM64_STOP_MMIO_ADDR
			&& kvm_run->mmio.is_write) {
			/* KVM advances the guest PC past the MMIO store only on the next
			   KVM_RUN entry -- against whatever PC is loaded then, so a later
			   set-PC + run (vmcall, reset) would skip its first instruction.
			   Complete the MMIO now: an immediate_exit run never enters the
			   guest, and KVM commits the pending PC increment on its way out. */
			kvm_run->immediate_exit = 1;
			ioctl(this->fd, KVM_RUN, 0);
			kvm_run->immediate_exit = 0;
			this->invalidate_register_cache();
			this->stopped = true;
			return 0;
		}
		if (kvm_run->mmio.phys_addr == ARM64_SYSCALL_MMIO_ADDR
			&& kvm_run->mmio.is_write) {
			const uint64_t ESR_EL1 = sys_reg_id(3, 0, 5, 2, 0);
			const uint64_t esr = get_sysreg(this->fd, ESR_EL1);
			const uint8_t ec = esr >> 26;
			if (ec == 0x24 || ec == 0x25) {
				if (handle_cow_data_abort(*this)) {
					return 1;
				}
			}
			if (ec != 0x15) {
				handle_exception(ec);
			}
			const unsigned syscall =
				(unsigned)*(const uint64_t*)kvm_run->mmio.data;
			{
				ScopedProfiler<MachineProfiling::Syscall> prof(machine().profiling());
				machine().system_call(*this, syscall);
			}
			if (this->timer_ticks && this->timed_out()) {
				Machine::timeout_exception("Timeout Exception", this->timer_ticks);
			}
			if (this->stopped) {
				/* Same deferred PC increment hazard as the stop exit above.
				   The handler may have modified registers; flush them so the
				   increment commits against the final PC. */
				this->flush_registers();
				kvm_run->immediate_exit = 1;
				ioctl(this->fd, KVM_RUN, 0);
				kvm_run->immediate_exit = 0;
				this->invalidate_register_cache();
				return 0;
			}
			return 1;
		}
		if (kvm_run->mmio.phys_addr >= ARM64_FATAL_MMIO_ADDR
			&& kvm_run->mmio.phys_addr < ARM64_FATAL_MMIO_ADDR + 0x800
			&& kvm_run->mmio.is_write) {
			if (handle_cow_data_abort(*this)) {
				return 1;
			}
			handle_exception(kvm_run->mmio.phys_addr - ARM64_FATAL_MMIO_ADDR);
		}
		Machine::machine_exception("Unhandled ARM64 MMIO exit", kvm_run->mmio.phys_addr);
	case KVM_EXIT_FAIL_ENTRY:
		Machine::machine_exception("Failed to start guest! Misconfigured?", KVM_EXIT_FAIL_ENTRY);
	case KVM_EXIT_INTERNAL_ERROR:
		Machine::machine_exception("KVM internal error", kvm_run->internal.suberror);
	default:
		Machine::machine_exception("Unhandled KVM exit reason", kvm_run->exit_reason);
	}
}

long Machine::step_one()
{
	return vcpu.run_once();
}

TINYKVM_COLD()
long Machine::run_with_breakpoints(std::array<uint64_t, 4>)
{
	throw MachineException("Hardware breakpoints are not implemented on ARM64");
}

TINYKVM_COLD()
void vCPU::print_registers() const
{
	const auto& regs = registers();
	const auto& printer = machine().m_printer;
	char buffer[1024];
	for (size_t i = 0; i < 31; i += 2) {
		if (i + 1 < 31) {
			PRINTER(printer, buffer, "X%02zu: 0x%016llX  X%02zu: 0x%016llX\n",
				i, regs.regs[i], i + 1, regs.regs[i + 1]);
		} else {
			PRINTER(printer, buffer, "X%02zu: 0x%016llX\n", i, regs.regs[i]);
		}
	}
	PRINTER(printer, buffer, "PC:  0x%016llX  SP:  0x%016llX  PSTATE: 0x%016llX\n",
		regs.pc, regs.sp, regs.pstate);
}

TINYKVM_COLD()
void vCPU::handle_exception(uint64_t intr)
{
	const uint64_t ESR_EL1 = sys_reg_id(3, 0, 5, 2, 0);
	const uint64_t FAR_EL1 = sys_reg_id(3, 0, 6, 0, 0);
	const uint64_t ELR_EL1 = sys_reg_id(3, 0, 4, 0, 1);
	const uint64_t esr = get_sysreg(this->fd, ESR_EL1);
	const uint64_t far = get_sysreg(this->fd, FAR_EL1);
	const uint64_t elr = get_sysreg(this->fd, ELR_EL1);
	this->print_registers();
	const auto& printer = machine().m_printer;
	char buffer[256];
	PRINTER(printer, buffer, "ESR_EL1: 0x%016llX EC: 0x%02X FAR_EL1: 0x%016llX ELR_EL1: 0x%016llX\n",
		(unsigned long long)esr, unsigned(esr >> 26),
		(unsigned long long)far, (unsigned long long)elr);
	Machine::machine_exception("Unhandled ARM64 guest exception", intr);
}

unsigned vCPU::exception_extra_offset(uint8_t)
{
	return 0;
}

void Machine::migrate_to_this_thread()
{
	timer_delete((timer_t)vcpu.timer_id);
	vcpu.timer_id = create_vcpu_timer();
}

} // namespace tinykvm
