#include <catch2/catch_test_macros.hpp>

#include <chrono>
#include <string>
#include <vector>
#include <tinykvm/machine.hpp>

/* The execution timer belongs to the thread, so every vCPU that runs on a
   thread arms and disarms the same one (see Machine::this_thread_vcpu_timer()).
   A run() nested inside another run() on that thread therefore has to hand the
   outer run's deadline back when it leaves, instead of disarming it: a syscall
   handler is free to run a second machine, and the outer guest is still under a
   deadline while it does.

   Without that, the inner run's disable_timer() disarms the timer that was
   protecting the outer run, which then sits in KVM_RUN with no timeout armed --
   an infinite loop in the outer guest hangs the thread for good.

   Arch-neutral: both backends share the timer per thread and both have their
   own copy of run(). */

extern std::vector<uint8_t> build_and_load(const std::string& code);

static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};
/* Below TINYKVM_MAX_SYSCALLS, and not one Linux uses. */
static constexpr unsigned SYSCALL_NESTED_RUN = 500;

/* The machine the syscall handler runs, and the flags it reports through.
   install_syscall_handler() takes a plain function pointer, so this state
   cannot be captured. */
static tinykvm::Machine* g_inner = nullptr;
static bool g_inner_ran = false;
static std::string g_inner_error;

static void run_inner_machine(tinykvm::vCPU&)
{
	g_inner_ran = true;
	try {
		/* A generous timeout, so the inner run arms the shared timer far past
		   the outer run's much shorter deadline. */
		g_inner->timed_vmcall(g_inner->address_of("quick"), 10.0f);
	} catch (const std::exception& e) {
		g_inner_error = e.what();
	}
}

TEST_CASE("A nested run leaves the outer run's timeout armed", "[timer]")
{
	tinykvm::Machine::init();

	/* Inner: returns immediately, called from the outer machine's handler. */
	const auto inner_binary = build_and_load(R"M(
int main() { return 0; }
extern long quick(void) { return 42; }
)M");
	tinykvm::Machine inner { inner_binary, { .max_mem = MAX_MEMORY } };
	inner.setup_linux({"inner"}, env);
	inner.run(8.0f);
	g_inner = &inner;

	/* Outer: runs the inner machine from a syscall, then spins forever. */
	const auto outer_binary = build_and_load(R"M(
#include <unistd.h>
int main() {
	syscall(500);
	while (1) { __asm__ volatile(""); }
	return 0;
}
)M");
	tinykvm::Machine outer { outer_binary, { .max_mem = MAX_MEMORY } };
	outer.setup_linux({"outer"}, env);
	tinykvm::Machine::install_syscall_handler(
		SYSCALL_NESTED_RUN, run_inner_machine);

	bool timed_out = false;
	std::string other_error;
	const auto started = std::chrono::steady_clock::now();
	try {
		outer.run(0.2f);
	} catch (const tinykvm::MachineTimeoutException&) {
		timed_out = true;
	} catch (const std::exception& e) {
		other_error = e.what();
	}
	const auto elapsed = std::chrono::duration<double>(
		std::chrono::steady_clock::now() - started).count();

	REQUIRE(g_inner_ran);
	REQUIRE(g_inner_error.empty());
	REQUIRE(other_error.empty());
	/* Hangs forever instead, if the inner run disarmed the outer's timer. */
	REQUIRE(timed_out);
	/* And the deadline is absolute, not restarted: the outer run's 200ms budget
	   keeps counting down across the nested run rather than beginning again
	   after it, which is how it behaved when every vCPU owned a timer. The
	   bound is loose enough not to be a timing test -- it only has to exclude
	   the inner run's own 10s timeout having been left in place. */
	REQUIRE(elapsed < 5.0);
}

TEST_CASE("A nested run does not consume the outer run's timeout", "[timer]")
{
	tinykvm::Machine::init();

	/* Same shape, but the outer guest returns straight after the syscall. A
	   restored deadline must not fire on a guest that is behaving: the outer
	   run has to complete normally, and the timer must be left disarmed for
	   whatever runs on this thread next. */
	const auto inner_binary = build_and_load(R"M(
int main() { return 0; }
extern long quick(void) { return 42; }
)M");
	tinykvm::Machine inner { inner_binary, { .max_mem = MAX_MEMORY } };
	inner.setup_linux({"inner2"}, env);
	inner.run(8.0f);
	g_inner = &inner;
	g_inner_ran = false;
	g_inner_error.clear();

	const auto outer_binary = build_and_load(R"M(
#include <unistd.h>
int main() {
	syscall(500);
	return 0;
}
)M");
	tinykvm::Machine outer { outer_binary, { .max_mem = MAX_MEMORY } };
	outer.setup_linux({"outer2"}, env);
	tinykvm::Machine::install_syscall_handler(
		SYSCALL_NESTED_RUN, run_inner_machine);

	std::string error;
	try {
		outer.run(4.0f);
	} catch (const std::exception& e) {
		error = e.what();
	}
	REQUIRE(g_inner_ran);
	REQUIRE(g_inner_error.empty());
	REQUIRE(error.empty());
	REQUIRE(!outer.cpu().timed_out());

	/* A second, plain run on this thread must still be timed correctly -- the
	   nested pair above left no arming behind. */
	tinykvm::Machine spinner { build_and_load(R"M(
int main() { while (1) { __asm__ volatile(""); } return 0; }
)M"), { .max_mem = MAX_MEMORY } };
	spinner.setup_linux({"spinner"}, env);
	bool timed_out = false;
	try {
		spinner.run(0.2f);
	} catch (const tinykvm::MachineTimeoutException&) {
		timed_out = true;
	}
	REQUIRE(timed_out);
}
