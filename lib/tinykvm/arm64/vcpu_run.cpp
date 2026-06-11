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

static uint64_t core_reg_id(uint64_t reg)
{
	return KVM_REG_ARM64 | KVM_REG_SIZE_U64 | KVM_REG_ARM_CORE | reg;
}

static void advance_pc_one_instruction(int fd)
{
	__u64 pc = 0;
	struct kvm_one_reg pc_reg {
		.id = core_reg_id(KVM_REG_ARM_CORE_REG(regs.pc)),
		.addr = (uint64_t)&pc,
	};
	if (ioctl(fd, KVM_GET_ONE_REG, &pc_reg) < 0) {
		throw MachineException("KVM_GET_ONE_REG pc failed", errno);
	}
	pc += 4;
	if (ioctl(fd, KVM_SET_ONE_REG, &pc_reg) < 0) {
		throw MachineException("KVM_SET_ONE_REG pc failed", errno);
	}
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
		result = ioctl(this->fd, KVM_RUN, 0);
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
			advance_pc_one_instruction(this->fd);
			this->stopped = true;
			return 0;
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
void vCPU::handle_exception(uint8_t intr)
{
	this->print_registers();
	Machine::machine_exception("ARM64 exception handling is not implemented", intr);
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
