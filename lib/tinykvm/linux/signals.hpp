#pragma once
#include "../forward.hpp"
#include <array>
#include <map>
#include <memory>
#include <vector>

namespace tinykvm {
struct vCPU;

struct SignalStack {
	/* Laid out as the guest's stack_t, so sigaltstack(2) can copy straight
	   in and out of it. SS_DISABLE with no stack is the initial state. */
	uint64_t ss_sp = 0x0;
	int      ss_flags = 2; /* SS_DISABLE */
	uint64_t ss_size = 0;

	bool is_enabled() const noexcept {
		return ss_sp != 0x0 && ss_size != 0 && (ss_flags & 2 /* SS_DISABLE */) == 0;
	}
};

struct SignalAction {
	static constexpr uint64_t SIG_UNSET = ~0ULL;
	/* sa_flags bits we act on. SA_SIGINFO is deliberately not among them: the
	   frame is built and RSI/RDX are handed over either way, exactly as Linux
	   does, so a handler declared without a prototype still finds them. */
	static constexpr uint64_t SA_F_RESTORER = 0x04000000;
	static constexpr uint64_t SA_F_ONSTACK  = 0x08000000;

	bool is_unset() const noexcept {
		return handler == 0x0 || handler == SIG_UNSET;
	}
	/* Delivery jumps straight to the handler (sysret on AMD64, eret on
	   ARM64), so a non-canonical address would fault inside the kernel
	   trampoline instead of merely crashing the guest. Anything the CPU
	   cannot enter usermode at is treated as no handler at all, which lands
	   the signal on its default disposition -- what Linux does too, only via
	   a SIGSEGV on the way. */
	bool is_deliverable() const noexcept {
		return !is_unset() && handler != 1 /* SIG_IGN */
			&& handler < 0x0000800000000000ULL;
	}

	bool on_altstack() const noexcept { return (flags & SA_F_ONSTACK) != 0; }
	/* x86-64 has no kernel-provided restorer: libcs must pass their own, and
	   the kernel rejects sigaction without SA_RESTORER. Guests that leave it
	   out get our usermode fallback stub instead of an immediate fault. */
	bool has_restorer() const noexcept {
		return (flags & SA_F_RESTORER) != 0 && restorer != 0x0
			&& restorer < 0x0000800000000000ULL;
	}

	uint64_t handler = SIG_UNSET;
	uint64_t flags = 0x0;
	unsigned mask = 0x0;
	uint64_t restorer = 0x0;
};

struct SignalReturn {
	/* Saved interrupted frames, innermost on top. Signal delivery pushes the
	   pre-signal frame; rt_sigreturn pops it. Nested signals need a stack so
	   an inner delivery does not overwrite the outer return context. */
	std::vector<tinykvm_regs> frames;
};

struct SignalPerThread {
	SignalStack  stack;
	SignalReturn sigret;
};

struct Signals {
	/* SI_TKILL: everything that reaches send() today arrives through
	   tgkill(2), which is also how glibc and the Go runtime implement
	   raise(). Guests branch on it -- Go's sigFromUser() treats SI_TKILL and
	   SI_USER as "not a fault", which is what keeps a preemption signal from
	   being mistaken for a SIGSEGV worth panicking on. */
	static constexpr int SI_TKILL = -6;
	static constexpr int SI_USER  = 0;

	SignalAction& get(int sig);
	void send(vCPU&, int sig, int si_code = SI_TKILL);
	void enter(vCPU&, int sig, int si_code = SI_TKILL);
	void sigreturn(vCPU&);

	// TODO: Lock this in the future, for multiproessing
	auto& per_thread(int tid) { return m_per_thread[tid]; }

	Signals();
	/* Copyable: forks inherit the master handlers, and reset_to() restores
	   them. Explicit, as the destructor deprecates the implicit ones. */
	Signals(const Signals&);
	Signals& operator=(const Signals&);
	~Signals();
private:
	std::array<SignalAction, 64> signals {};
	std::map<int, SignalPerThread> m_per_thread;
};


} // tinykvm
