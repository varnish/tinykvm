#pragma once
/**
 * Host-side seccomp-BPF sandbox for the TinyKVM VMM process.
 *
 * This is a second, kernel-enforced layer *behind* the guest-facing
 * syscall emulation in system_calls.cpp. The emulation layer decides
 * what the guest may ask for; this layer bounds what the VMM process
 * itself can execute if a handler is ever compromised.
 *
 * Two-phase model:
 *  - Phase::Init: wide allowlist for guest/master-VM initialization
 *    (ELF loading, dynamic linking, warm-fork prepare). Still excludes
 *    the host-takeover set (execve, ptrace, mount, bpf, ...).
 *  - Phase::Runtime: strict allowlist for serving requests. Installed
 *    on top of the init filter: seccomp filters stack and can only
 *    ever tighten - there is no way to loosen or remove one.
 *
 * IMPORTANT: filters are irrevocable and per-thread (or per-process
 * with all_threads=true). A thread-pool thread that installs a filter
 * stays filtered after it returns to the pool. Embedders that share
 * threads between TinyKVM and other work (e.g. a Varnish worker
 * process) must either dedicate threads to VM execution or run VMs in
 * their own process before enabling all_threads.
 */
#include <cstdint>
#include <vector>

namespace tinykvm {

enum class SeccompPhase {
	Init,    /* Wide: guest initialization, warm-fork prepare */
	Runtime, /* Strict: request serving after prepare() */
};

struct SeccompRule {
	enum class Action : uint8_t {
		Allow, /* Execute the system call */
		Errno, /* Fail the system call with `errnum`, do not execute */
	};
	/* Masked-equal argument constraint: (syscall_arg[index] & mask) == value.
	 * Constraints on the same rule are AND-ed. Multiple rules for the same
	 * syscall number are OR-ed (first match wins). BPF cannot dereference
	 * pointers, so only raw register values can be checked here. */
	struct Arg {
		uint8_t  index; /* 0..5 */
		uint64_t mask;
		uint64_t value;
	};

	uint32_t nr;
	Action   action = Action::Allow;
	uint16_t errnum = 0;
	uint8_t  num_args = 0;
	Arg      args[2] = {};

	constexpr SeccompRule(uint32_t nr_) : nr(nr_) {}
	constexpr SeccompRule(uint32_t nr_, Arg a0)
		: nr(nr_), num_args(1), args{a0, {}} {}
	constexpr SeccompRule(uint32_t nr_, Arg a0, Arg a1)
		: nr(nr_), num_args(2), args{a0, a1} {}
	static constexpr SeccompRule Errnum(uint32_t nr_, uint16_t err) {
		SeccompRule r{nr_};
		r.action = Action::Errno;
		r.errnum = err;
		return r;
	}
};

struct SeccompOptions {
	/* Log-and-allow instead of kill on violations (SECCOMP_RET_LOG).
	 * Use this to soak-test an allowlist: violations show up in the
	 * kernel audit log (dmesg / auditd, type=SECCOMP) but execution
	 * continues. Flip to false once the log stays quiet. */
	bool log_only = false;
	/* Apply to all threads of the process atomically (TSYNC) instead
	 * of only the calling thread. See the header comment before using
	 * this in an embedded (shared-process) context. */
	bool all_threads = false;
	/* Extra embedder-specific rules appended to the phase table. */
	std::vector<SeccompRule> extra_rules {};
};

/* Install the seccomp filter for the given phase on the calling thread
 * (or process, with all_threads). Sets PR_SET_NO_NEW_PRIVS. Irrevocable.
 * Throws MachineException on failure. Calling with Phase::Runtime after
 * Phase::Init stacks the filters, which is the intended usage. */
void install_seccomp_filter(SeccompPhase phase, const SeccompOptions& options = {});

/* The built-in allowlist for a phase, before extra_rules. Exposed so
 * embedders can inspect or derive their own tables. */
std::vector<SeccompRule> seccomp_rules_for(SeccompPhase phase);

} // tinykvm
