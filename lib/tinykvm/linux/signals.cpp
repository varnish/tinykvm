#include "../machine.hpp"
#include "threads.hpp"
#if defined(TINYKVM_ARCH_ARM64)
#include "../arm64/memory_layout.hpp"
#endif
#include <cerrno>
#include <csignal>

namespace tinykvm {

namespace {

bool default_ignored_signal(int sig)
{
	switch (sig) {
	case SIGCHLD:
	case SIGCONT:
	case SIGURG:
	case SIGWINCH:
		return true;
	default:
		return false;
	}
}

int signal_tid(vCPU& cpu)
{
	return cpu.machine().threads().gettid();
}

} // namespace

Signals::Signals() = default;
Signals::~Signals() = default;

SignalAction& Signals::get(int sig) {
	if (sig > 0 && sig <= static_cast<int>(signals.size()))
		return signals.at(sig-1);
	throw MachineException("Signal out of range", sig);
}

void Signals::send(vCPU& cpu, int sig)
{
	auto regs = cpu.registers();
	if (sig == 0) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}
	if (sig < 1 || sig > static_cast<int>(signals.size())) {
		regs.sysret() = -EINVAL;
		cpu.set_registers(regs);
		return;
	}

	const auto& sigact = get(sig);
	if (sigact.handler == 1 /* SIG_IGN */) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}
	if (!sigact.is_unset()) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		enter(cpu, sig);
		return;
	}
	if (default_ignored_signal(sig)) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}

	regs.sysret() = 128 + sig;
	cpu.set_registers(regs);
	cpu.stop();
}

void Signals::enter(vCPU& cpu, int sig)
{
	if (sig <= 0) return;
	auto& sigact = get(sig);

#if defined(TINYKVM_ARCH_ARM64)
	const int tid = signal_tid(cpu);
	auto& frames = per_thread(tid).sigret.frames;
	frames.push_back(cpu.registers());

	auto regs = frames.back();
	if (sigact.altstack) {
		auto& stack = per_thread(tid).stack;
		if (stack.ss_sp != 0x0) {
			regs.stackptr() = (stack.ss_sp + stack.ss_size) & ~uint64_t(0xF);
		}
	}

	regs.regs[0] = static_cast<__u64>(sig);
	regs.regs[30] = SIGRETURN_ADDR;
	regs.pc = sigact.handler;
	cpu.set_registers(regs);
#else
	auto& regs = cpu.registers();
	if (sigact.altstack) {
		const int tid = signal_tid(cpu);
		auto& stack = per_thread(tid).stack;
		if (stack.ss_sp != 0x0) {
			regs.stackptr() = stack.ss_sp + stack.ss_size;
		}
	}

	regs.sysarg(0) = static_cast<__u64>(sig);
	regs.rcx = sigact.handler;
	cpu.set_registers(regs);
#endif
}

void Signals::sigreturn(vCPU& cpu)
{
	const int tid = signal_tid(cpu);
	auto& frames = per_thread(tid).sigret.frames;
	if (frames.empty()) {
		cpu.stop();
		return;
	}
	cpu.set_registers(frames.back());
	frames.pop_back();
}

SignalAction& Machine::sigaction(int sig)
{
	return signals().get(sig);
}

} // tinykvm
