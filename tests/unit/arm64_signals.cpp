#include <catch2/catch_test_macros.hpp>

#include <csignal>
#include <string>
#include <utility>
#include <vector>
#include <tinykvm/machine.hpp>

extern std::pair<std::string, std::vector<uint8_t>>
	build_and_load(const std::string& code, const std::string& args);

static const uint64_t MAX_MEMORY = 64ul << 20; /* 64MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

static void require_arm64_kvm()
{
	static bool attempted = false;
	static bool available = false;
	static std::string error;
	if (!attempted) {
		attempted = true;
		try {
			tinykvm::Machine::init();
			available = true;
		} catch (const tinykvm::MachineException& e) {
			error = std::string(e.what()) + " (" + std::to_string(e.data()) + ")";
		}
	}
	if (!available) {
		SKIP("ARM64 KVM unavailable: " << error);
	}
}

TEST_CASE("ARM64 signal handler runs and resumes", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int got = 0;
static volatile int got_sig = -1;
static void handler(int s) { got = 1; got_sig = s; }
int main() {
	if (signal(SIGUSR1, handler) == SIG_ERR) return 1;
	raise(SIGUSR1);
	if (!got) return 2;
	if (got_sig != SIGUSR1) return 3;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 signal preserves interrupted context", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile long scratch = 0;
static void handler(int s) { (void)s; scratch = 0xDEADBEEF; }
int main() {
	signal(SIGUSR1, handler);
	volatile long a = 11, b = 31, c = 0;
	for (long i = 0; i < 1000; i++) c += a * b;
	int rc = raise(SIGUSR1);
	c += a + b;
	if (rc != 0) return 1;
	if (scratch != (long)0xDEADBEEF) return 2;
	if (c != 341042) return 3;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 repeated signal delivery", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int count = 0;
static void handler(int s) { (void)s; count++; }
int main() {
	signal(SIGUSR1, handler);
	for (int i = 0; i < 1000; i++) raise(SIGUSR1);
	return count == 1000 ? 666 : count;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 SIG_IGN is dropped", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	signal(SIGUSR1, SIG_IGN);
	if (raise(SIGUSR1) != 0) return 1;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 signal runs on alternate stack", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <stdint.h>
#define ALTSZ (64 * 1024)
static char altbuf[ALTSZ] __attribute__((aligned(16)));
static volatile int on_alt = 0;
static void handler(int s) {
	(void)s;
	uintptr_t fp = (uintptr_t)__builtin_frame_address(0);
	uintptr_t lo = (uintptr_t)altbuf;
	uintptr_t hi = lo + sizeof(altbuf);
	on_alt = (fp >= lo && fp < hi);
}
int main() {
	stack_t ss;
	memset(&ss, 0, sizeof ss);
	ss.ss_sp = altbuf;
	ss.ss_size = sizeof(altbuf);
	if (sigaltstack(&ss, 0) != 0) return 1;
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	sa.sa_flags = SA_ONSTACK;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 2;
	raise(SIGUSR1);
	return on_alt ? 666 : 3;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 unhandled fatal signal terminates VM", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	raise(SIGUSR1);
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 128 + SIGUSR1);
}

TEST_CASE("ARM64 signal delivered to a worker thread", "[arm64][signals][threads]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <pthread.h>
#include <signal.h>
static volatile int got = 0;
static void handler(int s) { (void)s; got++; }
static void* worker(void* arg) {
	(void)arg;
	for (int i = 0; i < 50; i++) raise(SIGUSR1);
	return (void*)(unsigned long)got;
}
int main() {
	signal(SIGUSR1, handler);
	pthread_t t;
	if (pthread_create(&t, 0, worker, 0) != 0) return 1;
	void* ret = 0;
	if (pthread_join(t, &ret) != 0) return 2;
	if ((long)(unsigned long)ret != 50) return 3;
	if (got != 50) return 4;
	return 666;
})M", "-pthread");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 nested signal delivery preserves outer frame", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int order = 0;
static void h2(int s) { (void)s; order = order * 10 + 2; }
static void h1(int s) {
	(void)s;
	order = order * 10 + 1;
	raise(SIGUSR2);
	order = order * 10 + 1;
}
int main() {
	signal(SIGUSR1, h1);
	signal(SIGUSR2, h2);
	raise(SIGUSR1);
	return order == 121 ? 666 : order;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}
