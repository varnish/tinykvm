#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <thread>
#include <vector>
#include <tinykvm/machine.hpp>

/* The vCPU execution timer belongs to the thread that runs the vCPU, not to
   the vCPU and not to a VM group seat. Three things follow, and this file pins
   all three:

   1. Building a pool of forks creates no timers at all -- the count tracks the
      number of *threads that have run a guest*, not the number of forks (and
      not the number of seats). That is the point of the change.
   2. A fork that migrates to another thread still times out there. This is the
      case the old per-vCPU/per-seat timer needed explicit rebind logic for: a
      timer bound (SIGEV_THREAD_ID) to a thread that is no longer running the
      vCPU neither interrupts the KVM_RUN that has to be interrupted, nor stays
      quiet on the thread it is still bound to.
   3. ...and the thread it migrated away from is not left holding a timer that
      fires into whatever runs there next.

   /proc/self/timers is the only place a POSIX timer is visible; it needs
   CONFIG_CHECKPOINT_RESTORE, and the counting cases self-skip without it. */

extern std::vector<uint8_t> build_and_load(const std::string& code);

static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const uint64_t MAX_COWMEM =  4ul << 20; /* 4MB */
static constexpr int POOL_SIZE = 64;
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

/* Whether a *pooled* fork can be made to execute here. On ARM64 it cannot, on
   this project's test host: the nested KVM_RUN that arm64_flush_guest_tlb()
   issues for a pooled member's deferred TTBR0 flush never returns. That is
   pre-existing and reproduces on the unmodified branch -- it is not something
   the timer has any part in -- so the cases that need a pooled fork to *run*
   are left to the AMD64 lane. Pooled construction and seat reuse, which is
   where a seat used to acquire and rebind a timer, are checked on both. */
#if defined(TINYKVM_ARCH_ARM64)
static constexpr bool POOLED_CAN_RUN = false;
#else
static constexpr bool POOLED_CAN_RUN = true;
#endif

static void require_kvm()
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
		SKIP("KVM unavailable: " << error);
	}
}

static size_t count_posix_timers()
{
	FILE* f = fopen("/proc/self/timers", "r");
	if (f == nullptr)
		return SIZE_MAX; /* CONFIG_CHECKPOINT_RESTORE=n */
	size_t count = 0;
	char line[256];
	while (fgets(line, sizeof(line), f) != nullptr) {
		if (strncmp(line, "ID:", 3) == 0)
			count += 1;
	}
	fclose(f);
	return count;
}

/* A master exporting a function that returns immediately and one that spins
   forever, so a fork can be made to both finish and time out on demand. */
static tinykvm::Machine& forkable_master()
{
	static const std::vector<uint8_t> binary = build_and_load(R"M(
int main() { return 0; }
extern long quick(void) { return 42; }
extern void spin(void) { while (1) { __asm__ volatile(""); } }
)M");
	static tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	static bool prepared = false;
	if (!prepared) {
		prepared = true;
		machine.setup_linux({"timer"}, env);
		machine.run(8.0f);
		machine.prepare_copy_on_write();
	}
	return machine;
}

static tinykvm::MachineOptions fork_options(bool pooled)
{
	tinykvm::MachineOptions options;
	options.max_mem = MAX_MEMORY;
	options.max_cow_mem = MAX_COWMEM;
	options.vm_group = pooled;
	return options;
}

TEST_CASE("A pool of forks holds no execution timers", "[timer]")
{
	require_kvm();
	auto& master = forkable_master();
	if (count_posix_timers() == SIZE_MAX) {
		SKIP("/proc/self/timers unavailable (CONFIG_CHECKPOINT_RESTORE=n)");
	}
	/* The master ran above, so this thread already has its one timer -- and
	   while nothing else runs, it is the only one the process holds. */
	REQUIRE(count_posix_timers() == 1);

	for (const bool pooled : {false, true}) {
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (int i = 0; i < POOL_SIZE; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine>(
				master, fork_options(pooled)));
		}
		/* POOL_SIZE live forks, none run: neither a fork nor a seat owns a
		   timer. Before the change this was POOL_SIZE + 1. */
		REQUIRE(count_posix_timers() == 1);

		if (pooled && !POOLED_CAN_RUN) {
			continue;
		}
		const auto quick = forks.front()->address_of("quick");
		REQUIRE(quick != 0x0);
		for (auto& fork : forks) {
			fork->timed_vmcall(quick, 8.0f);
		}
		/* Running them changes nothing either: they all ran on this thread. */
		REQUIRE(count_posix_timers() == 1);
	}
	/* And the forks going away takes nothing with it that was not there. */
	REQUIRE(count_posix_timers() == 1);
}

TEST_CASE("A seat handed between threads costs no timer", "[timer][vm_group]")
{
	require_kvm();
	auto& master = forkable_master();
	if (count_posix_timers() == SIZE_MAX) {
		SKIP("/proc/self/timers unavailable (CONFIG_CHECKPOINT_RESTORE=n)");
	}
	const size_t before = count_posix_timers();

	/* Take a seat, hand it back, take it again from a different thread, twice
	   over. Each hand-off used to be a timer_delete() plus a timer_create()
	   because the seat's timer was bound to the previous tenant's thread. */
	for (int i = 0; i < 8; i++) {
		std::thread thread([&] {
			tinykvm::Machine fork {master, fork_options(true)};
			fork.migrate_to_this_thread();
			REQUIRE(fork.is_forked());
		});
		thread.join();
	}
	REQUIRE(count_posix_timers() == before);
}

TEST_CASE("A fork that migrates threads still times out on its new thread", "[timer]")
{
	require_kvm();
	auto& master = forkable_master();

	for (const bool pooled : {false, true}) {
		if (pooled && !POOLED_CAN_RUN) {
			continue;
		}
		tinykvm::Machine fork {master, fork_options(pooled)};
		const auto quick = fork.address_of("quick");
		const auto spin  = fork.address_of("spin");
		REQUIRE(quick != 0x0);
		REQUIRE(spin  != 0x0);

		/* Thread A: run once, so the fork is unambiguously bound to a thread
		   that is not the one it is about to time out on. */
		std::string error;
		std::thread thread_a([&] {
			try {
				fork.migrate_to_this_thread();
				fork.timed_vmcall(quick, 8.0f);
			} catch (const std::exception& e) {
				error = e.what();
			}
		});
		thread_a.join();
		REQUIRE(error.empty());

		/* Thread B: the guest spins forever, and the 100ms timeout has to
		   interrupt *this* thread's KVM_RUN. A timer left bound to thread A
		   would leave this hanging until the suite is killed. */
		bool timed_out = false;
		std::thread thread_b([&] {
			fork.migrate_to_this_thread();
			try {
				fork.timed_vmcall(spin, 0.1f);
			} catch (const tinykvm::MachineTimeoutException&) {
				timed_out = true;
			} catch (const std::exception& e) {
				error = e.what();
			}
		});
		thread_b.join();
		REQUIRE(error.empty());
		REQUIRE(timed_out);
	}
}

TEST_CASE("A timeout leaves no timer firing on the thread it migrated from", "[timer]")
{
	require_kvm();
	auto& master = forkable_master();
	tinykvm::Machine fork {master, fork_options(false)};
	const auto quick = fork.address_of("quick");
	const auto spin  = fork.address_of("spin");
	REQUIRE(quick != 0x0);
	REQUIRE(spin  != 0x0);

	/* Time out on thread A. The timer's 20ms re-arm interval is what made a
	   stale binding dangerous: it keeps firing at whichever thread the timer
	   is bound to, timing out whatever innocent guest runs there next. */
	bool timed_out = false;
	std::string error;
	std::thread thread_a([&] {
		fork.migrate_to_this_thread();
		try {
			fork.timed_vmcall(spin, 0.1f);
		} catch (const tinykvm::MachineTimeoutException&) {
			timed_out = true;
		} catch (const std::exception& e) {
			error = e.what();
		}
	});
	thread_a.join();
	REQUIRE(error.empty());
	REQUIRE(timed_out);

	/* A short, well-behaved call back on this thread must complete. The
	   generous timeout means only a *spurious* signal can fail it. */
	fork.migrate_to_this_thread();
	fork.timed_vmcall(quick, 8.0f);

	/* One timer per thread that ran a guest: this one, plus thread A's -- and
	   thread A's went away when thread A did. */
	const size_t timers = count_posix_timers();
	if (timers != SIZE_MAX) {
		REQUIRE(timers == 1);
	}
}
