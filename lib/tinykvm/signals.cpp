#include "machine.hpp"
#include "threads.hpp"

namespace tinykvm {

Signals::Signals() {}
Signals::~Signals() {}

SignalAction& Signals::get(int sig) {
	if (sig > 0)
		return signals.at(sig-1);
	throw MachineException("Signal 0 invoked", sig);
}

void Signals::enter(vCPU& cpu, int sig)
{
	if (sig == 0) return;
	auto& regs = cpu.registers();

	auto& sigact = signals.at(sig);
	if (sigact.altstack) {
		const int tid = cpu.machine().threads().gettid();
		// Change to alternate per-thread stack
		auto& stack = per_thread(tid).stack;
		// But only if non-zero
		if (stack.ss_sp != 0x0) {
			regs.rsp = stack.ss_sp + stack.ss_size;
		}
	}

	//cpu.machine().enter_usermode();
	regs.rcx = sigact.handler;
	cpu.set_registers(regs);
}

} // tinykvm
