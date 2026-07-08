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
	const int status = run_in_child([&] {
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Init);
		/* uname is init-only; allowed now... */
		struct utsname { char data[65 * 6]; } uts;
		if (syscall(SYS_uname, &uts) != 0)
			_exit(1);
		tinykvm::install_seccomp_filter(tinykvm::SeccompPhase::Runtime);
		/* ...and fatal after tightening. */
		syscall(SYS_uname, &uts);
		_exit(2); /* not reached */
	});
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
