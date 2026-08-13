#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/linux/seccomp.hpp>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

/* Seccomp filters are irrevocable for the installing thread, so every
 * test installs the filter in a forked child and inspects its fate. */
template <typename Fn>
static int run_in_child(Fn&& fn)
{
	fflush(nullptr);
	const pid_t pid = fork();
	REQUIRE(pid != -1);
	if (pid == 0) {
		fn(); /* must _exit() itself; falling through is a failure */
		_exit(111);
	}
	int status = -1;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	return status;
}

TEST_CASE("Guest runs under the strict runtime filter", "[Seccomp]")
{
	tinykvm::Machine::init();
	/* Compile in the parent: the compiler needs execve, which no
	 * phase of the sandbox allows. */
	const auto binary = build_and_load(R"M(
#include <stdio.h>
int main() {
	printf("hello sandboxed world\n");
	return 666;
})M");

	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		/* Machine construction, KVM ioctls, timers, guest syscalls -
		 * everything from here on runs under the strict filter. */
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
		machine.setup_linux({"seccomp"}, env);
		machine.run(4.0f);
		_exit(machine.return_value() == 666 ? 0 : 1);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Runtime filter kills on a banned syscall", "[Seccomp]")
{
	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		syscall(SYS_chroot, "/"); /* not in any allowlist */
		_exit(0); /* not reached */
	});
	REQUIRE(WIFSIGNALED(status));
	REQUIRE(WTERMSIG(status) == SIGSYS);
}

TEST_CASE("Log-only mode lets banned syscalls through", "[Seccomp]")
{
	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime,
			{ .log_only = true });
		syscall(SYS_chroot, "/"); /* logged (audit), fails with EPERM */
		_exit(0);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Init then runtime filters stack", "[Seccomp]")
{
	/* The child reports over a pipe that it survived installing the
	 * Runtime filter, so the SIGSYS below provably comes from uname
	 * and not from the seccomp() call being blocked by the Init filter. */
	int fds[2];
	REQUIRE(pipe(fds) == 0);
	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Init);
		/* uname is init-only; allowed now... */
		struct utsname { char data[65 * 6]; } uts;
		if (syscall(SYS_uname, &uts) != 0)
			_exit(1);
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		char ok = '!';
		if (write(fds[1], &ok, 1) != 1)
			_exit(3);
		/* ...and fatal after tightening. */
		syscall(SYS_uname, &uts);
		_exit(2); /* not reached */
	});
	close(fds[1]);
	char ok = 0;
	REQUIRE(read(fds[0], &ok, 1) == 1);
	close(fds[0]);
	REQUIRE(WIFSIGNALED(status));
	REQUIRE(WTERMSIG(status) == SIGSYS);
}

TEST_CASE("Arg filtering: non-KVM ioctls are blocked", "[Seccomp]")
{
	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		/* TCGETS on stdout: syscall number is allowed, request is not */
		struct { char data[64]; } tio;
		ioctl(1, 0x5401 /* TCGETS */, &tio);
		_exit(0); /* not reached */
	});
	REQUIRE(WIFSIGNALED(status));
	REQUIRE(WTERMSIG(status) == SIGSYS);
}

TEST_CASE("Malformed extra rules are rejected", "[Seccomp]")
{
	/* Run in a child anyway: if validation regresses, the filter (or
	 * NO_NEW_PRIVS) must not stick to the test runner's thread. */
	const int status = run_in_child([&] {
		tinykvm::SeccompOptions opts;
		tinykvm::SeccompRule bad_index{SYS_uname, {6 /* > 5 */, ~0ULL, 0}};
		opts.extra_rules.push_back(bad_index);
		try {
			tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime, opts);
			_exit(1);
		} catch (const std::exception&) {}
		tinykvm::SeccompRule bad_count{SYS_uname};
		bad_count.num_args = 3; /* > sizeof(args) */
		opts.extra_rules = {bad_count};
		try {
			tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime, opts);
			_exit(2);
		} catch (const std::exception&) {}
		_exit(0);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Extra rules extend the allowlist", "[Seccomp]")
{
	const int status = run_in_child([&] {
		tinykvm::SeccompOptions opts;
		opts.extra_rules.push_back(tinykvm::SeccompRule{SYS_uname});
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime, opts);
		struct utsname { char data[65 * 6]; } uts;
		_exit(syscall(SYS_uname, &uts) == 0 ? 0 : 1);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

/* --------------------------------------------------------------------- */
/* Regression tests for runtime-allowlist omissions. The syscall          */
/* emulation layer (linux/system_calls.cpp) legitimately performs these   */
/* host syscalls on behalf of an ordinary guest, but the Runtime filter   */
/* does not allow them, so the VMM process is killed by SIGSYS. Each test */
/* asserts the correct behavior (guest completes under the filter) and    */
/* currently FAILS: the child dies with SIGSYS.                           */
/* --------------------------------------------------------------------- */

TEST_CASE("Runtime filter allows guest epoll_wait", "[Seccomp]")
{
	/* The emulated epoll_wait handler waits on the host with
	   SYS_epoll_pwait2 (system_calls.cpp), which is missing from the
	   runtime allowlist (only epoll_wait/epoll_pwait are listed). */
	const auto binary = build_and_load(R"M(
#include <sys/epoll.h>
int main() {
	int e = epoll_create1(0);
	if (e < 0) return 10;
	struct epoll_event ev[4];
	int r = epoll_wait(e, ev, 4, 0);
	return (r >= 0) ? 42 : 11;
})M");

	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
		machine.setup_linux({"seccomp"}, env);
		machine.run(4.0f);
		_exit(machine.return_value() == 42 ? 0 : 1);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Runtime filter allows guest fsync", "[Seccomp]")
{
	/* The emulated fsync handler passes the call through to the host fd,
	   but SYS_fsync is missing from the runtime allowlist. */
	const auto binary = build_and_load(R"M(
#include <unistd.h>
int main() {
	fsync(1); /* result does not matter; the host call must be allowed */
	return 43;
})M");

	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
		machine.setup_linux({"seccomp"}, env);
		machine.run(4.0f);
		_exit(machine.return_value() == 43 ? 0 : 1);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Runtime filter allows guest fchmod", "[Seccomp]")
{
	/* The emulated fchmod handler passes the call through to the host fd,
	   but SYS_fchmod is missing from the runtime allowlist. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <sys/stat.h>
int main() {
	fchmod(1, 0); /* result does not matter; the host call must be allowed */
	return 44;
})M");

	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
		machine.setup_linux({"seccomp"}, env);
		machine.run(4.0f);
		_exit(machine.return_value() == 44 ? 0 : 1);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}

TEST_CASE("Runtime filter allows guest ftruncate", "[Seccomp]")
{
	/* The emulated ftruncate handler passes the call through to the host
	   fd, but SYS_ftruncate is only in the init-phase allowlist, not the
	   runtime one. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <unistd.h>
int main() {
	ftruncate(1, 0); /* result does not matter; the host call must be allowed */
	return 45;
})M");

	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
		machine.setup_linux({"seccomp"}, env);
		machine.run(4.0f);
		_exit(machine.return_value() == 45 ? 0 : 1);
	});
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);
}
