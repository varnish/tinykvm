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

static long run_guest(const std::vector<uint8_t>& binary, const std::string& name)
{
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({name}, env);
	machine.run(8.0f);
	return machine.return_value();
}

// 1. The narrowest proof that a registered handler runs and then RETURNS:
//    raise(SIGUSR1) must invoke the handler (which sets a flag) and then
//    resume the interrupted code so raise() returns 0 and main continues.
TEST_CASE("ARM64 signal handler runs and returns", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile sig_atomic_t got = 0;
static void handler(int sig) { got = sig; }
int main() {
	struct sigaction sa = {0};
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;
	if (raise(SIGUSR1) != 0) return 2;   /* must return here after handler */
	if (got != SIGUSR1) return 3;        /* handler must have run */
	return 666;
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-basic") == 666);
}

// 2. SA_SIGINFO delivery: the handler receives a valid siginfo_t* and
//    ucontext*; check the signal number arrives through siginfo.
TEST_CASE("ARM64 SA_SIGINFO handler receives siginfo", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
#include <stddef.h>
static volatile int seen_signo = -1;
static volatile int seen_nonnull = 0;
static void handler(int sig, siginfo_t* si, void* uc) {
	(void)sig;
	seen_signo   = si ? si->si_signo : -2;
	seen_nonnull = (si != NULL) && (uc != NULL);
}
int main() {
	struct sigaction sa = {0};
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGUSR2, &sa, 0) != 0) return 1;
	if (raise(SIGUSR2) != 0) return 2;
	if (seen_signo != SIGUSR2) return 3;
	if (!seen_nonnull) return 4;
	return 777;
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-siginfo") == 777);
}

// 3. Register and FP/SIMD state must survive across signal delivery. The
//    handler deliberately clobbers integer and floating-point registers; the
//    interrupted computation must still produce the right result on return.
TEST_CASE("ARM64 signal preserves integer and FP state", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile double sink;
static void handler(int sig) {
	(void)sig;
	/* Trash a pile of FP registers so a missing save/restore shows up. */
	double acc = 1.0;
	for (int i = 0; i < 64; i++) acc = acc * 1.5 + (double)i;
	sink = acc;
}
int main() {
	struct sigaction sa = {0};
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;

	/* Values computed before the signal, held live across raise(); all are
	   exactly representable so equality comparisons are valid. */
	double keep = 0.0;
	for (int i = 0; i < 16; i++) keep += (double)i * 0.5; /* 60.0 */
	long acc = 0;
	for (long i = 0; i < 1000; i++) acc += i;             /* 499500 */
	if (raise(SIGUSR1) != 0) return 2;
	if (keep != 60.0) return 3;       /* FP state survived the handler */
	if (acc != 499500) return 4;      /* integer state survived too */
	return 555;
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-fpstate") == 555);
}

// 4. SIG_IGN: an explicitly ignored signal is dropped, raise() returns 0,
//    and the VM keeps running (it must not terminate).
TEST_CASE("ARM64 SIG_IGN drops the signal", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	signal(SIGUSR1, SIG_IGN);
	if (raise(SIGUSR1) != 0) return 2;
	return 444;
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-ign") == 444);
}

// 5. A handler can re-arm and be entered more than once (nested in time, not
//    in stack): two raises must invoke the handler twice and both must return.
TEST_CASE("ARM64 handler is re-entrant across separate raises", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile sig_atomic_t count = 0;
static void handler(int sig) { (void)sig; count++; }
int main() {
	struct sigaction sa = {0};
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;
	if (raise(SIGUSR1) != 0) return 2;
	if (raise(SIGUSR1) != 0) return 3;
	if (count != 2) return 4;
	return 222;
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-reenter") == 222);
}

// 6. Default disposition is unchanged: a fatal signal with no handler still
//    terminates the VM with the shell-convention 128+signo status.
TEST_CASE("ARM64 unhandled fatal signal terminates with 128+signo", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	raise(SIGTERM);   /* no handler -> VM terminates */
	return 1;         /* must not be reached */
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-default") == 128 + SIGTERM);
}

// 7. Signal delivery inside a worker thread. raise() in a multithreaded
//    program targets the calling thread (tgkill with that thread's tid), so
//    this exercises the per-thread saved-context path (current_sig_tid() with
//    a real, non-main tid) that Python/Node worker threads rely on.
TEST_CASE("ARM64 signal delivered to a worker thread", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
#include <pthread.h>
static volatile sig_atomic_t got = 0;
static void handler(int sig) { got = sig; }
static void* worker(void* arg) {
	(void)arg;
	if (raise(SIGUSR1) != 0) return (void*)1UL; /* delivered to this thread */
	if (got != SIGUSR1)      return (void*)2UL; /* handler ran */
	return (void*)123UL;                        /* resumed correctly */
}
int main() {
	struct sigaction sa = {0};
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;
	pthread_t t;
	if (pthread_create(&t, 0, worker, 0) != 0) return 2;
	void* ret = 0;
	if (pthread_join(t, &ret) != 0) return 3;
	if ((long)(unsigned long)ret != 123) return 4;
	return 888;
})M", "-pthread -D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-thread") == 888);
}

// 8. kill(getpid(), sig) reaches a handler too. glibc's kill() issues the
//    kill syscall (129), a different entry point from raise()/tgkill (131).
TEST_CASE("ARM64 kill(getpid()) delivers to handler", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
#include <unistd.h>
static volatile sig_atomic_t got = 0;
static void handler(int sig) { got = sig; }
int main() {
	struct sigaction sa = {0};
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;
	if (kill(getpid(), SIGUSR1) != 0) return 2;
	if (got != SIGUSR1) return 3;
	return 999;
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-kill") == 999);
}

// 9. abort() raises SIGABRT; with no handler it must terminate the VM with
//    128+SIGABRT (and not throw out of the host, which the old tkill stub did).
TEST_CASE("ARM64 abort() terminates with 128+SIGABRT", "[arm64][signals]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <stdlib.h>
int main() {
	abort();
	return 1; /* unreachable */
})M", "-D_GNU_SOURCE");

	REQUIRE(run_guest(binary, "sig-abort") == 128 + SIGABRT);
}
