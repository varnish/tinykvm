#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const uint64_t MAX_COWMEM =  8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

TEST_CASE("Execute function in reset VM", "[Reset]")
{
	const auto binary = build_and_load(R"M(
static int a = 0;
static int b = 1;
int main() {
}
extern long get_a() {
	int ta = a;
	a = 333;
	return ta;
}
extern long get_b() {
	int tb = b;
	b = 666;
	return tb;
}
extern long get_mmap(int *z) {
	int total = z[100] + z[200] + z[300] + z[400];
	z[100] = 22;
	z[200] = 44;
	z[300] = 66;
	z[400] = 88;
	return total;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"reset"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	// Make machine forkable (no working memory)
	machine.prepare_copy_on_write(0);

	auto maddr = machine.mmap_allocate(0x1000);

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	for (size_t i = 0; i < 15; i++)
	{
		auto& m = fork;
		m.timed_vmcall(m.address_of("get_a"), 2.0f);
		REQUIRE(m.return_value() == 0);

		m.timed_vmcall(m.address_of("get_b"), 2.0f);
		REQUIRE(m.return_value() == 1);

		m.timed_vmcall(m.address_of("get_mmap"), 2.0f, (uint64_t)maddr);
		REQUIRE(m.return_value() == 0);

		m.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});
	}
}

TEST_CASE("Execute function in VM (crash recovery)", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#include <assert.h>
#include <stdio.h>
int main() {
	printf("Main!\n");
}

__asm__(".global some_syscall\n"
	".type some_syscall, @function\n"
	"some_syscall:\n"
	".cfi_startproc\n"
	"	mov $0x10000, %eax\n"
	"	out %eax, $0\n"
	"	ret\n"
	".cfi_endproc\n");
extern long some_syscall();

extern long hello_world(const char *arg) {
	printf("%s\n", arg);
	fflush(stdout);
	return some_syscall();
}
extern void crash(const char *arg) {
	some_syscall();
	printf("%s\n", arg);
	fflush(stdout);
	some_syscall();
	assert(0);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"reset"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	// Make machine forkable (no working memory)
	machine.prepare_copy_on_write(0);

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	tinykvm::Machine::install_unhandled_syscall_handler(
	[] (tinykvm::vCPU& cpu, unsigned scall) {
		auto regs = cpu.registers();
		switch (scall) {
			case 0x10000: // Some function
				regs.rax = 1023;
				break;
			default:
				regs.rax = -ENOSYS;
		}
		cpu.set_registers(regs);
	});

	bool output_is_hello_world = false;
	fork.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		if (text == "Hello World!")
			output_is_hello_world = true;
	});

	// Print and crash, verify recovery after reset
	for (size_t i = 0; i < 15; i++)
	{
		auto& m = fork;

		output_is_hello_world = false;
		m.timed_vmcall(m.address_of("hello_world"), 2.0f, "Hello World!");
		REQUIRE(m.return_value() == 1023);
		REQUIRE(output_is_hello_world);

		output_is_hello_world = false;
		m.timed_vmcall(m.address_of("hello_world"), 2.0f, "Hello World!");
		REQUIRE(m.return_value() == 1023);
		REQUIRE(output_is_hello_world);

		output_is_hello_world = false;
		try {
			m.timed_vmcall(m.address_of("crash"), 2.0f, "Hello World!");
		} catch (...) {}
		REQUIRE(output_is_hello_world);

		m.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});
	}
}

/* --------------------------------------------------------------------- */
/* Regression tests for cross-request state leaks through reset_to().     */
/* A fork is a "request"; reset_to(master) must return it to the master's */
/* pristine state. Each test below asserts the correct behavior and       */
/* currently FAILS on the unpatched tree: the mutated state survives the  */
/* reset and leaks into the next request.                                 */
/* --------------------------------------------------------------------- */
#include <tinykvm/linux/signals.hpp>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

TEST_CASE("brk is restored to the master value by reset_to", "[Reset]")
{
	/* The guest raises its brk inside a fork (one request). reset_to() must
	   restore brk to the master's frozen value; currently the raised brk
	   survives (ratcheted against brk_end), leaking heap growth -- and any
	   data left on it -- into the next request. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
int main() { return 0; }
extern long grow_brk(void) {
	long cur = syscall(SYS_brk, 0);
	syscall(SYS_brk, cur + 0x200000); /* grow by 2MB */
	return syscall(SYS_brk, 0);
}
extern long get_brk(void) {
	return syscall(SYS_brk, 0);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	const uint64_t master_brk = machine.brk_address();
	REQUIRE(fork.brk_address() == master_brk);

	/* Request: the guest grows its brk by 2MB. */
	fork.timed_vmcall(fork.address_of("grow_brk"), 2.0f);
	REQUIRE(fork.return_value() > master_brk);

	fork.reset_to(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM
	});

	/* Next request: brk must be back at the master's value. */
	CHECK(fork.brk_address() == master_brk);
	fork.timed_vmcall(fork.address_of("get_brk"), 2.0f);
	CHECK(fork.return_value() == master_brk);
}

TEST_CASE("signal handlers are cleared by reset_to", "[Reset]")
{
	/* A guest that installs a signal handler inside a fork (one request)
	   must not keep that handler after reset_to(). Currently the handler
	   leaks: it is still installed after the reset and keeps executing in
	   the next request. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <unistd.h>
#include <sys/syscall.h>
static volatile int counter = 0;
static void handler(int sig) { (void)sig; counter++; }
int main() { return 0; }
extern long install_handler(void) {
	struct sigaction sa; memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	return sigaction(SIGUSR1, &sa, NULL);
}
extern long query_handler(void) {
	struct sigaction sa; memset(&sa, 0, sizeof sa);
	sigaction(SIGUSR1, NULL, &sa);
	return (long)sa.sa_handler;
}
extern long fire_and_count(void) {
	counter = 0;
	syscall(SYS_tgkill, getpid(), syscall(SYS_gettid), SIGUSR1);
	return counter;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	REQUIRE(fork.sigaction(SIGUSR1).is_unset());

	/* Request: install a SIGUSR1 handler and verify it fires. */
	fork.timed_vmcall(fork.address_of("install_handler"), 2.0f);
	REQUIRE(fork.return_value() == 0);
	fork.timed_vmcall(fork.address_of("fire_and_count"), 2.0f);
	REQUIRE(fork.return_value() == 1);

	fork.reset_to(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM
	});

	/* Next request: the handler must be gone (SIG_DFL, never runs). */
	CHECK(fork.sigaction(SIGUSR1).is_unset());
	fork.timed_vmcall(fork.address_of("query_handler"), 2.0f);
	CHECK(fork.return_value() == 0);
	fork.timed_vmcall(fork.address_of("fire_and_count"), 2.0f);
	CHECK(fork.return_value() == 0);
}

namespace {
	/* Two scratch directories, each holding a "rel" file with distinct
	   content; the host process's cwd is restored on destruction. */
	struct CwdDirs {
		std::string dirA, dirB, saved_cwd;

		CwdDirs()
		{
			char tmplA[] = "/tmp/tinykvm-reset-cwdA-XXXXXX";
			char tmplB[] = "/tmp/tinykvm-reset-cwdB-XXXXXX";
			REQUIRE(mkdtemp(tmplA) != nullptr);
			REQUIRE(mkdtemp(tmplB) != nullptr);
			dirA = tmplA;
			dirB = tmplB;
			write_rel(dirA, "AAAA");
			write_rel(dirB, "BBBB");
			char cwdbuf[4096];
			REQUIRE(getcwd(cwdbuf, sizeof(cwdbuf)) != nullptr);
			saved_cwd = cwdbuf;
		}
		~CwdDirs()
		{
			chdir(saved_cwd.c_str());
			unlink((dirA + "/rel").c_str());
			unlink((dirB + "/rel").c_str());
			rmdir(dirA.c_str());
			rmdir(dirB.c_str());
		}
		static void write_rel(const std::string& dir, const char* data)
		{
			const int fd = open((dir + "/rel").c_str(), O_WRONLY | O_CREAT, 0644);
			REQUIRE(fd >= 0);
			REQUIRE(write(fd, data, 4) == 4);
			close(fd);
		}
	};
}

TEST_CASE("reset_to preserves the master working directory", "[Reset]")
{
	/* FileDescriptors::reset_to() rebuilds the fd table but never restores
	   m_current_working_directory{,_fd} from the master, so AT_FDCWD in a
	   fork resolves against the VMM process's *host* cwd instead of the
	   master's configured directory. The guest below opens the relative
	   path "rel" and prints its content plus getcwd(); the correct answer
	   is the master's directory and file in every case. */
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
static char buf[256];
int main() { return 0; }
extern void do_check(void) {
	int fd = open("rel", O_RDONLY);
	if (fd < 0) {
		write(1, "OPENFAIL", 8);
	} else {
		int n = read(fd, buf, 4);
		close(fd);
		if (n > 0) write(1, buf, n);
	}
	write(1, " cwd=[", 6);
	char* r = getcwd(buf, sizeof(buf));
	if (r) write(1, buf, strlen(buf));
	write(1, "]", 1);
})M");

	CwdDirs dirs;
	const std::string expected = "AAAA cwd=[" + dirs.dirA + "]";
	auto approve_all = [](std::string&) { return true; };

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.fds().set_open_readable_callback(approve_all);
	std::string mout;
	machine.set_printer([&](const char* d, size_t s) { mout.append(d, s); });
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.fds().set_current_working_directory(dirs.dirA);

	/* Sanity: the master itself resolves "rel" against its configured cwd. */
	machine.timed_vmcall(machine.address_of("do_check"), 4.0f);
	REQUIRE(mout == expected);

	machine.prepare_copy_on_write(65536);
	/* The VMM process's host cwd is now somewhere else, with a different
	   "rel" file -- resolving against it is the bug. */
	REQUIRE(chdir(dirs.dirB.c_str()) == 0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	/* Re-install the policy callbacks on the fork, as an embedder would. */
	fork.fds().set_open_readable_callback(approve_all);
	std::string fout;
	fork.set_printer([&](const char* d, size_t s) { fout.append(d, s); });

	/* A fresh fork must resolve "rel" against the master's cwd. */
	fork.timed_vmcall(fork.address_of("do_check"), 4.0f);
	CHECK(fout == expected);

	/* ... and so must the same fork after reset_to(). */
	fork.reset_to(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM
	});
	fork.fds().set_open_readable_callback(approve_all);
	fout.clear();
	fork.timed_vmcall(fork.address_of("do_check"), 4.0f);
	CHECK(fout == expected);
}
