#pragma once
#include "../forward.hpp"
#include <array>
#include <map>
#include <memory>
#include <vector>

namespace tinykvm {
struct vCPU;

struct SignalStack {
	uint64_t ss_sp = 0x0;
	int      ss_flags = 0x0;
	uint64_t ss_size = 0;
};

struct SignalAction {
	static constexpr uint64_t SIG_UNSET = ~0ULL;

	bool is_unset() const noexcept {
		return handler == 0x0 || handler == SIG_UNSET;
	}

	uint64_t handler = SIG_UNSET;
	bool altstack = false;
	unsigned mask = 0x0;
	uint64_t restorer = 0x0;
};

struct SignalReturn {
	tinykvm_regs regs;
};

/* Snapshot of an interrupted EL0 context, saved when a signal handler is
   entered and restored by rt_sigreturn. ARM64 only: the full register and
   FP/SIMD state are kept host-side (a LIFO per thread, so nested handlers
   work) rather than parsed back out of the guest's signal frame. */
struct SavedSignalContext {
	tinykvm_regs   regs;  // GP regs; pc/sp hold the user values, pstate=SPSR_EL1
	tinykvm_fpuregs fpu;
};

struct SignalPerThread {
	SignalStack  stack;
	SignalReturn sigret;
	std::vector<SavedSignalContext> saved; // ARM64 rt_sigreturn restore stack
};

struct Signals {
	SignalAction& get(int sig);
	void enter(vCPU&, int sig);

	// TODO: Lock this in the future, for multiproessing
	auto& per_thread(int tid) { return m_per_thread[tid]; }

	Signals();
	~Signals();
private:
	std::array<SignalAction, 64> signals {};
	std::map<int, SignalPerThread> m_per_thread;
};


} // tinykvm
