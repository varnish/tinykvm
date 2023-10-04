#pragma once
#include "forward.hpp"
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
};

struct SignalReturn {
	tinykvm_x86regs regs;
};

struct SignalPerThread {
	SignalStack  stack;
	SignalReturn sigret;
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
