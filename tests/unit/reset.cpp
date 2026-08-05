#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/linux/fds.hpp>
#include <csignal>
#include <cstdio>
#include <fcntl.h>
#include <unistd.h>
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

/**
 * The tests below cover host-side state that lives in a fork: anything
 * reset_to() fails to restore is carried into the next VM call.
 */

TEST_CASE("Signal handlers are inherited by forks and restored by reset_to", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <signal.h>
#include <stddef.h>

static volatile int usr1_hits = 0;
static void usr1_handler(int sig) { (void)sig; usr1_hits++; }

int main() {
	/* Installed on the master: forks must inherit it. */
	signal(SIGUSR2, usr1_handler);
}

extern long install_usr1() {
	return (signal(SIGUSR1, usr1_handler) == SIG_ERR) ? -1 : 0;
}
/* Returns the handler the guest sees through oldact. */
extern long query(int sig) {
	struct sigaction old;
	if (sigaction(sig, NULL, &old) < 0)
		return -1;
	return (long)old.sa_handler;
}
extern long install_chld() {
	return (signal(SIGCHLD, usr1_handler) == SIG_ERR) ? -1 : 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	/* Inherited from the master, and never touched by anyone. */
	REQUIRE(!fork.sigaction(SIGUSR2).is_unset());
	REQUIRE(fork.sigaction(SIGUSR1).is_unset());

	for (size_t i = 0; i < 3; i++)
	{
		/* A never-set handler must read back as SIG_DFL (0). */
		fork.timed_vmcall(fork.address_of("query"), 2.0f, (int)SIGUSR1);
		REQUIRE(fork.return_value() == 0);

		fork.timed_vmcall(fork.address_of("install_usr1"), 2.0f);
		REQUIRE(fork.return_value() == 0);
		REQUIRE(!fork.sigaction(SIGUSR1).is_unset());

		fork.timed_vmcall(fork.address_of("install_chld"), 2.0f);
		REQUIRE(fork.return_value() == 0);
		REQUIRE(!fork.sigaction(SIGCHLD).is_unset());

		fork.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});

		/* Both must be gone: is_unset() is what Signals::send() consults, so
		   an installed handler here is one that would still be entered. */
		REQUIRE(fork.sigaction(SIGUSR1).is_unset());
		REQUIRE(fork.sigaction(SIGCHLD).is_unset());
		/* And the guest must see the same through oldact. */
		fork.timed_vmcall(fork.address_of("query"), 2.0f, (int)SIGUSR1);
		REQUIRE(fork.return_value() == 0);

		/* The master's own handler survives every reset. */
		REQUIRE(!fork.sigaction(SIGUSR2).is_unset());
	}
}

TEST_CASE("brk is restored to the master value by reset_to", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>

int main() {
}
extern long get_brk() {
	/* brk(0) is refused as a shrink and returns the current break. */
	return syscall(SYS_brk, 0);
}
extern long raise_brk() {
	long cur = syscall(SYS_brk, 0);
	return syscall(SYS_brk, cur + 0x100000);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	const auto master_brk = machine.brk_address();
	REQUIRE(master_brk != 0x0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	REQUIRE(fork.brk_address() == master_brk);

	for (size_t i = 0; i < 3; i++)
	{
		fork.timed_vmcall(fork.address_of("get_brk"), 2.0f);
		REQUIRE(uint64_t(fork.return_value()) == master_brk);

		fork.timed_vmcall(fork.address_of("raise_brk"), 2.0f);
		REQUIRE(uint64_t(fork.return_value()) > master_brk);
		REQUIRE(fork.brk_address() > master_brk);

		fork.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});

		/* Both the host-side scalar and the guest-visible break must be back
		   at the master value. */
		REQUIRE(fork.brk_address() == master_brk);
	}
}

TEST_CASE("reset_to preserves the master working directory", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int main() {
}
/* Opens a relative path, resolved against the guest cwd fd. */
extern long read_relative() {
	char buf[8];
	memset(buf, 0, sizeof(buf));
	int fd = open("rel", O_RDONLY);
	if (fd < 0) return -1;
	ssize_t n = read(fd, buf, 4);
	close(fd);
	if (n != 4) return -2;
	return (long)(unsigned char)buf[0];
}
extern long cwd_matches(const char *expected) {
	char buf[512];
	memset(buf, 0, sizeof(buf));
	if (getcwd(buf, sizeof(buf)) == NULL) return -1;
	return strcmp(buf, expected) == 0 ? 1 : 0;
})M");

	/* A directory the host process is not sitting in, holding a file that
	   only resolves relative to it. */
	char dir_template[] = "/tmp/tinykvm-cwd-XXXXXX";
	const char* dir = mkdtemp(dir_template);
	REQUIRE(dir != nullptr);
	const std::string master_dir = dir;
	const std::string relfile = master_dir + "/rel";
	{
		FILE* f = fopen(relfile.c_str(), "wb");
		REQUIRE(f != nullptr);
		REQUIRE(fwrite("AAAA", 1, 4, f) == 4);
		fclose(f);
	}

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.fds().set_current_working_directory(master_dir);
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	/* Policy callbacks are not inherited from the master, so they are
	   installed on the fork. The path is approved unmodified, and so it stays
	   relative and must resolve through the guest working-directory fd. */
	fork.fds().set_open_readable_callback([](std::string&) { return true; });

	for (size_t i = 0; i < 3; i++)
	{
		REQUIRE(fork.fds().current_working_directory() == master_dir);

		fork.timed_vmcall(fork.address_of("cwd_matches"), 2.0f, master_dir.c_str());
		REQUIRE(fork.return_value() == 1);

		/* If the fork resolved against AT_FDCWD (the host process cwd) there
		   is no "rel" there, and this is -1. */
		fork.timed_vmcall(fork.address_of("read_relative"), 2.0f);
		REQUIRE(fork.return_value() == 'A');

		fork.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});
	}

	unlink(relfile.c_str());
	rmdir(master_dir.c_str());
}

TEST_CASE("Reconstructed pipes keep the master pipe2 flags", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

static int pfd[2];

int main() {
	/* Created on the master. Forks get a fresh pipe pair reusing the same
	   virtual fds. */
	if (pipe2(pfd, O_NONBLOCK) < 0) return 1;
}
extern long is_nonblocking() {
	int flags = fcntl(pfd[0], F_GETFL);
	if (flags < 0) return -1;
	return (flags & O_NONBLOCK) ? 1 : 0;
}
/* A blocking read on an empty pipe pins the host thread inside the SYS_read
   handler, where the timeout cannot fire. Non-blocking gives EAGAIN. */
extern long read_empty() {
	char buf[4];
	ssize_t n = read(pfd[0], buf, sizeof(buf));
	if (n >= 0) return -1;
	return errno == EAGAIN ? 1 : 0;
}
extern long roundtrip() {
	char buf[4] = {0,0,0,0};
	if (write(pfd[1], "PING", 4) != 4) return -1;
	if (read(pfd[0], buf, 4) != 4) return -2;
	return buf[0] == 'P' ? 1 : 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	/* The master really did create a non-blocking pipe. */
	REQUIRE(machine.fds().get_socket_pairs().size() == 1);
	REQUIRE(machine.fds().get_socket_pairs()[0].type ==
		tinykvm::FileDescriptors::SocketType::PIPE2);
	REQUIRE((machine.fds().get_socket_pairs()[0].flags & O_NONBLOCK) != 0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	for (size_t i = 0; i < 3; i++)
	{
		fork.timed_vmcall(fork.address_of("is_nonblocking"), 2.0f);
		REQUIRE(fork.return_value() == 1);

		fork.timed_vmcall(fork.address_of("read_empty"), 2.0f);
		REQUIRE(fork.return_value() == 1);

		/* The pair is still a working pipe, not just a non-blocking one. */
		fork.timed_vmcall(fork.address_of("roundtrip"), 2.0f);
		REQUIRE(fork.return_value() == 1);

		/* Leave a byte in the pipe: the next turn must not see it. */
		fork.timed_vmcall(fork.address_of("roundtrip"), 2.0f);
		REQUIRE(fork.return_value() == 1);

		fork.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});
	}
}

TEST_CASE("Open file descriptors do not survive reset_to", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#include <fcntl.h>
#include <unistd.h>

int main() {
}
/* Deliberately leaks the fd, the way a VM call that dies mid-flight would. */
extern long leak_fd() {
	return open("/leakme", O_RDONLY);
}
extern long read_from(int fd) {
	char buf[4];
	return read(fd, buf, sizeof(buf));
})M");

	char file_template[] = "/tmp/tinykvm-leak-XXXXXX";
	const int tmpfd = mkstemp(file_template);
	REQUIRE(tmpfd >= 0);
	REQUIRE(write(tmpfd, "AAAA", 4) == 4);
	close(tmpfd);
	const std::string leakpath = file_template;

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"reset"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(0);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	fork.fds().set_open_readable_callback([&](std::string& path) {
		if (path != "/leakme") return false;
		path = leakpath;
		return true;
	});

	const auto fds_after_reset = [&] {
		return fork.fds().get_current_fds_opened();
	};

	int first_leaked_vfd = -1;
	for (size_t i = 0; i < 3; i++)
	{
		const auto before = fds_after_reset();

		fork.timed_vmcall(fork.address_of("leak_fd"), 2.0f);
		const int vfd = (int)fork.return_value();
		REQUIRE(vfd > 0);
		if (first_leaked_vfd < 0) {
			first_leaked_vfd = vfd;
		} else {
			/* The virtual fd counter is restored too, so every turn hands out
			   the same number rather than drifting upwards. */
			REQUIRE(vfd == first_leaked_vfd);
		}
		REQUIRE(fds_after_reset() == before + 1);

		fork.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});

		/* The leaked fd is closed and unmapped by the reset ... */
		REQUIRE(fds_after_reset() == before);
		/* ... and stdin/stdout/stderr are still there for the next turn. */
		REQUIRE(before == 3);

		/* Reading from the stale vfd must fail, not read the leaked file. */
		fork.timed_vmcall(fork.address_of("read_from"), 2.0f, vfd);
		REQUIRE(fork.return_value() < 0);
	}

	unlink(leakpath.c_str());
}
