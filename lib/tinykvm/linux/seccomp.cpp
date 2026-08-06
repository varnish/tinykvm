#include "seccomp.hpp"

#include "../common.hpp"
#include <cerrno>
#include <cstddef>
#include <cstring>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

/* Fallbacks for older kernel headers */
#ifndef SECCOMP_RET_KILL_PROCESS
#define SECCOMP_RET_KILL_PROCESS 0x80000000U
#endif
#ifndef SECCOMP_RET_LOG
#define SECCOMP_RET_LOG 0x7ffc0000U
#endif
#ifndef SECCOMP_FILTER_FLAG_TSYNC
#define SECCOMP_FILTER_FLAG_TSYNC (1UL << 0)
#endif
#ifndef SYS_seccomp
#if defined(__x86_64__)
#define SYS_seccomp 317
#elif defined(__aarch64__)
#define SYS_seccomp 277
#else
#error "No SYS_seccomp fallback for this architecture"
#endif
#endif

#if defined(__x86_64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#define SECCOMP_AUDIT_ARCH AUDIT_ARCH_AARCH64
#else
#error "Unsupported seccomp architecture"
#endif

namespace tinykvm {

/* All KVM ioctls have type byte 0xAE (bits 8..15 of the request). */
static constexpr uint64_t IOCTL_TYPE_MASK = 0xFF00;
static constexpr uint64_t IOCTL_TYPE_KVM  = 0xAE00;

static std::vector<SeccompRule> runtime_rules()
{
	using R = SeccompRule;
	std::vector<SeccompRule> rules {
		/* --- KVM_RUN loop --- */
		/* Any KVM ioctl (type 0xAE), on any fd */
		R{SYS_ioctl, {1, IOCTL_TYPE_MASK, IOCTL_TYPE_KVM}},
		/* ioctls passed through for guest fds (system_calls.cpp) */
		R{SYS_ioctl, {1, ~0ULL, FIONBIO}},
		R{SYS_ioctl, {1, ~0ULL, FIONREAD}},

		/* --- I/O on translated fds --- */
		R{SYS_read}, R{SYS_write}, R{SYS_readv}, R{SYS_writev},
		R{SYS_pread64}, R{SYS_pwrite64}, R{SYS_preadv}, R{SYS_pwritev},
		R{SYS_lseek}, R{SYS_close}, R{SYS_fstat}, R{SYS_newfstatat},
		R{SYS_statx}, R{SYS_fcntl}, R{SYS_dup}, R{SYS_dup3},
		R{SYS_getdents64},
		/* Mutating operations on already-translated fds. The fd was
		 * approved when it was opened; these do not widen that. */
		R{SYS_fsync}, R{SYS_fchmod}, R{SYS_ftruncate},
		/* Path-based, mediated by is_readable_path/is_writable_path.
		 * BPF cannot see the path; depth belongs to the emulation layer. */
		R{SYS_openat}, R{SYS_readlinkat}, R{SYS_faccessat},
#ifdef SYS_openat2
		/* The openat handler prefers openat2 with RESOLVE_* hardening */
		R{SYS_openat2},
#endif
#ifdef SYS_faccessat2
		R{SYS_faccessat2},
#endif

		/* --- Guest + VMM memory management --- */
		R{SYS_mmap}, R{SYS_munmap}, R{SYS_mprotect}, R{SYS_madvise},
		R{SYS_mremap}, R{SYS_brk}, R{SYS_membarrier},

		/* --- Networking (sockaddrs validated by the emulation layer) --- */
		R{SYS_socket}, R{SYS_socketpair}, R{SYS_connect}, R{SYS_bind},
		R{SYS_listen}, R{SYS_accept4}, R{SYS_getsockname}, R{SYS_getpeername},
		R{SYS_setsockopt}, R{SYS_getsockopt}, R{SYS_sendto}, R{SYS_recvfrom},
		R{SYS_sendmsg}, R{SYS_recvmsg}, R{SYS_sendmmsg}, R{SYS_recvmmsg},
		R{SYS_shutdown}, R{SYS_pipe2}, R{SYS_eventfd2},

		/* --- Event loops --- */
		R{SYS_epoll_create1}, R{SYS_epoll_ctl}, R{SYS_epoll_pwait},
		R{SYS_ppoll},
#ifdef SYS_epoll_pwait2
		/* preempt_epoll_wait() is on by default, and that path issues
		 * epoll_pwait2 rather than the epoll_wait the guest asked for. */
		R{SYS_epoll_pwait2},
#endif
#ifdef SYS_epoll_wait
		R{SYS_epoll_wait},
#endif
#ifdef SYS_poll
		R{SYS_poll},
#endif

		/* --- Time and execution timeouts (vcpu_run.cpp) --- */
		R{SYS_clock_gettime}, R{SYS_clock_getres}, R{SYS_clock_nanosleep},
		R{SYS_timer_create}, R{SYS_timer_settime}, R{SYS_timer_gettime},
		R{SYS_timer_delete},
		R{SYS_timerfd_create}, R{SYS_timerfd_settime}, R{SYS_timerfd_gettime},
#ifdef SYS_nanosleep
		R{SYS_nanosleep},
#endif
#ifdef SYS_gettimeofday
		R{SYS_gettimeofday},
#endif

		/* --- Signals (timeout delivery, guest signal emulation) --- */
		R{SYS_rt_sigaction}, R{SYS_rt_sigprocmask}, R{SYS_rt_sigreturn},
		R{SYS_sigaltstack}, R{SYS_tgkill},

		/* --- Threads and synchronization --- */
		/* New threads only: clone must carry CLONE_VM|CLONE_THREAD.
		 * Process-creating clone/fork belongs to the init phase. */
		R{SYS_clone, {0, CLONE_VM | CLONE_THREAD, CLONE_VM | CLONE_THREAD}},
		/* clone3 passes flags in a struct BPF can't read: deny with
		 * ENOSYS so glibc falls back to the filterable clone. */
#ifdef SYS_clone3
		R::Errnum(SYS_clone3, ENOSYS),
#endif
		R{SYS_futex}, R{SYS_set_robust_list},
#ifdef SYS_rseq
		R{SYS_rseq},
#endif
		R{SYS_sched_yield}, R{SYS_sched_getaffinity},
		R{SYS_gettid}, R{SYS_getpid},
		R{SYS_prctl, {0, ~0ULL, PR_SET_NAME}},
		R{SYS_prctl, {0, ~0ULL, PR_GET_NAME}},

		/* --- Process lifetime and misc --- */
		R{SYS_exit}, R{SYS_exit_group}, R{SYS_restart_syscall},
		R{SYS_getrandom},
	};
	return rules;
}

static std::vector<SeccompRule> init_rules()
{
	using R = SeccompRule;
	auto rules = runtime_rules();
	const std::vector<SeccompRule> extra {
		/* Unrestricted clone: cross-process warm forks, GDB fork() in
		 * machine_debug.cpp, and pre-thread setup. */
		R{SYS_clone}, R{SYS_wait4}, R{SYS_kill},
#ifdef SYS_fork
		R{SYS_fork},
#endif
		/* Process/runtime setup done by glibc and the ELF loader */
#ifdef SYS_arch_prctl
		R{SYS_arch_prctl},
#endif
		R{SYS_set_tid_address}, R{SYS_prlimit64},
		R{SYS_prctl}, R{SYS_getrlimit},
		/* Installing the Runtime filter from under the Init filter uses
		 * the seccomp() syscall. Filters only stack and tighten, so
		 * allowing this cannot loosen the sandbox. */
		R{SYS_seccomp, {0, ~0ULL, SECCOMP_SET_MODE_FILTER}},
		R{SYS_getuid}, R{SYS_geteuid}, R{SYS_getgid}, R{SYS_getegid},
		R{SYS_uname}, R{SYS_sysinfo}, R{SYS_sched_setaffinity},
		/* Wider filesystem access for loading guests and libraries */
		R{SYS_statfs}, R{SYS_fstatfs}, R{SYS_getcwd}, R{SYS_chdir},
		R{SYS_fchdir}, R{SYS_mkdirat}, R{SYS_unlinkat}, R{SYS_renameat},
		R{SYS_renameat2}, R{SYS_symlinkat}, R{SYS_linkat},
		R{SYS_fallocate}, R{SYS_copy_file_range},
		R{SYS_sendfile}, R{SYS_flock}, R{SYS_umask}, R{SYS_memfd_create},
		R{SYS_msync}, R{SYS_mincore}, R{SYS_mlock}, R{SYS_munlock},
		/* unsafe_syscalls mode (setup_linux_system_calls) */
		R{SYS_inotify_init1}, R{SYS_inotify_add_watch}, R{SYS_inotify_rm_watch},
		/* Unrestricted ioctl during setup (terminal probing etc.) */
		R{SYS_ioctl},
#ifdef SYS_open
		R{SYS_open}, R{SYS_stat}, R{SYS_lstat}, R{SYS_access},
		R{SYS_readlink}, R{SYS_pipe}, R{SYS_dup2}, R{SYS_select},
		R{SYS_mkdir}, R{SYS_unlink}, R{SYS_rename}, R{SYS_symlink},
#endif
		R{SYS_pselect6},
		/* NOTE: execve/execveat, ptrace, process_vm_{readv,writev},
		 * mount, pivot_root, bpf, kexec_load, init_module, setuid,
		 * userfaultfd, io_uring_* are deliberately absent even here:
		 * no legitimate guest init needs them from the VMM process. */
	};
	rules.insert(rules.end(), extra.begin(), extra.end());
	return rules;
}

std::vector<SeccompRule> seccomp_rules_for(SeccompPhase phase)
{
	return (phase == SeccompPhase::Init) ? init_rules() : runtime_rules();
}

/* --- BPF program emission --- */

static constexpr uint32_t SECCOMP_DATA_NR   = offsetof(struct seccomp_data, nr);
static constexpr uint32_t SECCOMP_DATA_ARCH = offsetof(struct seccomp_data, arch);
static uint32_t seccomp_data_arg_lo(unsigned idx) {
	return offsetof(struct seccomp_data, args) + idx * sizeof(uint64_t);
}
static uint32_t seccomp_data_arg_hi(unsigned idx) {
	return seccomp_data_arg_lo(idx) + sizeof(uint32_t);
}

static uint32_t rule_return_value(const SeccompRule& rule)
{
	switch (rule.action) {
	case SeccompRule::Action::Errno:
		return SECCOMP_RET_ERRNO | (rule.errnum & SECCOMP_RET_DATA);
	case SeccompRule::Action::Allow:
	default:
		return SECCOMP_RET_ALLOW;
	}
}

/* One rule becomes a self-contained block:
 *   LD  nr
 *   JEQ rule.nr        ? fall through : skip to next block
 *   per arg-half check: LD half; [AND mask]; JEQ value ? next : next block
 *   RET action
 * Failed checks fall to the next block, so several rules for the same
 * syscall number OR together. */
static void emit_rule_block(std::vector<struct sock_filter>& prog,
                            const SeccompRule& rule)
{
	/* num_args and Arg::index are public and settable via extra_rules:
	 * validate before they index args[] and seccomp_data.args. */
	constexpr unsigned MAX_ARGS = sizeof(rule.args) / sizeof(rule.args[0]);
	if (rule.num_args > MAX_ARGS)
		throw MachineException("seccomp: rule has too many argument "
			"constraints", rule.nr);

	struct Check { uint32_t off; uint32_t mask; uint32_t value; };
	Check checks[2 * MAX_ARGS];
	unsigned num_checks = 0;
	for (unsigned i = 0; i < rule.num_args; i++) {
		const auto& arg = rule.args[i];
		if (arg.index > 5)
			throw MachineException("seccomp: rule argument index out of "
				"range", rule.nr);
		const uint32_t mask_lo = arg.mask, mask_hi = arg.mask >> 32;
		const uint32_t val_lo = arg.value, val_hi = arg.value >> 32;
		if (mask_lo != 0)
			checks[num_checks++] = {seccomp_data_arg_lo(arg.index), mask_lo, val_lo};
		if (mask_hi != 0)
			checks[num_checks++] = {seccomp_data_arg_hi(arg.index), mask_hi, val_hi};
	}

	/* Compute block length to encode "jump past this block" offsets */
	unsigned block_len = 2 + 1; /* LD nr + JEQ nr + RET */
	for (unsigned i = 0; i < num_checks; i++)
		block_len += (checks[i].mask == 0xFFFFFFFFu) ? 2 : 3;

	const size_t base = prog.size();
	auto to_next_block = [&](void) -> uint8_t {
		/* jf is relative to the instruction after the jump; the jump
		 * was already pushed, so target(block_len) - emitted-so-far. */
		const unsigned emitted = prog.size() - base;
		return uint8_t(block_len - emitted);
	};

	prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR));
	prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, rule.nr, 0, 0));
	prog.back().jf = to_next_block();
	for (unsigned i = 0; i < num_checks; i++) {
		prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, checks[i].off));
		if (checks[i].mask != 0xFFFFFFFFu)
			prog.push_back(BPF_STMT(BPF_ALU | BPF_AND | BPF_K, checks[i].mask));
		prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, checks[i].value, 0, 0));
		prog.back().jf = to_next_block();
	}
	prog.push_back(BPF_STMT(BPF_RET | BPF_K, rule_return_value(rule)));
}

static std::vector<struct sock_filter>
build_program(const std::vector<SeccompRule>& rules, uint32_t default_action)
{
	std::vector<struct sock_filter> prog;
	prog.reserve(rules.size() * 4 + 8);

	/* Wrong architecture: always kill, even in log mode */
	prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_ARCH));
	prog.push_back(BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SECCOMP_AUDIT_ARCH, 1, 0));
	prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#if defined(__x86_64__)
	/* Reject x32 ABI syscalls (nr >= 0x40000000): same numbers, different ABI */
	prog.push_back(BPF_STMT(BPF_LD | BPF_W | BPF_ABS, SECCOMP_DATA_NR));
	prog.push_back(BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000u, 0, 1));
	prog.push_back(BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));
#endif

	for (const auto& rule : rules)
		emit_rule_block(prog, rule);

	prog.push_back(BPF_STMT(BPF_RET | BPF_K, default_action));
	if (prog.size() > BPF_MAXINSNS)
		throw MachineException("seccomp: filter exceeds BPF_MAXINSNS", prog.size());
	return prog;
}

void install_seccomp_filter(SeccompPhase phase, const SeccompOptions& options)
{
	auto rules = seccomp_rules_for(phase);
	rules.insert(rules.end(),
		options.extra_rules.begin(), options.extra_rules.end());

	const uint32_t default_action =
		options.log_only ? SECCOMP_RET_LOG : SECCOMP_RET_KILL_PROCESS;
	auto prog = build_program(rules, default_action);

	struct sock_fprog fprog {};
	fprog.len = uint16_t(prog.size());
	fprog.filter = prog.data();

	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0)
		throw MachineException("seccomp: PR_SET_NO_NEW_PRIVS failed", errno);

	const unsigned flags = options.all_threads ? SECCOMP_FILTER_FLAG_TSYNC : 0;
	const long res = syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, flags, &fprog);
	if (res != 0) {
		/* With TSYNC, a positive result is the TID of a thread whose
		 * existing filter conflicts with ours. */
		if (res > 0)
			throw MachineException("seccomp: TSYNC failed, thread has a "
				"conflicting filter (result is its TID)", res);
		throw MachineException("seccomp: SECCOMP_SET_MODE_FILTER failed", errno);
	}
}

} // tinykvm
