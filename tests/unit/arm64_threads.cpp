#include <catch2/catch_test_macros.hpp>

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

// 1. The narrowest possible proof that the green-thread engine works end to
//    end: spawn one pthread (clone + CLONE_SETTLS), pass an argument, write a
//    shared global, return a value, and join (futex WAIT on the child tid,
//    woken by the child's CLONE_CHILD_CLEARTID clear on exit).
TEST_CASE("ARM64 pthread create/join with shared memory", "[arm64][threads]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <pthread.h>
static long shared = 0;
static void* worker(void* arg) {
	shared = (long)(unsigned long)arg + 42;
	return (void*)(unsigned long)(shared + 1);
}
int main() {
	pthread_t t;
	if (pthread_create(&t, 0, worker, (void*)100UL) != 0) return 1;
	void* ret = 0;
	if (pthread_join(t, &ret) != 0) return 2;
	if (shared != 142) return 3;
	if ((long)(unsigned long)ret != 143) return 4;
	return 666;
})M", "-pthread");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_mmap_syscalls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"threads"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

// 2. Mutex contention across several threads. Uncontended glibc mutex
//    lock/unlock never traps, so this mainly exercises thread creation,
//    cooperative hand-off on exit, and join ordering with more than two
//    threads live at once.
TEST_CASE("ARM64 mutex-guarded counter across threads", "[arm64][threads]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <pthread.h>
#define N 4
#define ITERS 25000
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static volatile long counter = 0;
static void* worker(void* arg) {
	(void)arg;
	for (int i = 0; i < ITERS; i++) {
		pthread_mutex_lock(&lock);
		counter++;
		pthread_mutex_unlock(&lock);
	}
	return 0;
}
int main() {
	pthread_t t[N];
	for (int i = 0; i < N; i++)
		if (pthread_create(&t[i], 0, worker, 0) != 0) return 1;
	for (int i = 0; i < N; i++)
		pthread_join(t[i], 0);
	return counter == (long)N * ITERS ? 666 : 2;
})M", "-pthread");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"threads"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

// 3. Condition-variable producer/consumer. This is the case the TODO flags as
//    a real blocking hand-off (consumer waits, producer signals).
//
//    KNOWN-FAILING (tagged !shouldfail so it does not break the suite): this
//    deadlocks today. glibc's condvar uses FUTEX_WAIT_BITSET/FUTEX_WAKE, and
//    the ARM64 futex handler wakes "the next suspended thread regardless of
//    which address it waited on". Under the condvar/join handshake a wakeup is
//    delivered to the wrong waiter, the consumer misses a signal, and both
//    threads end up parked (consumer in cond_wait, main in pthread_join) ->
//    Timeout. The fix is address-aware futex wake (track the wait address per
//    suspended thread). When that lands, this test passes and the tag must be
//    removed (Catch2 reports a passing !shouldfail test as a failure).
TEST_CASE("ARM64 condition variable producer/consumer", "[arm64][threads][!shouldfail]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <pthread.h>
static pthread_mutex_t m = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;
static int ready = 0;
static long produced = 0, consumed = 0;
#define ITEMS 100
static void* consumer(void* arg) {
	(void)arg;
	for (int i = 0; i < ITEMS; i++) {
		pthread_mutex_lock(&m);
		while (!ready) pthread_cond_wait(&cv, &m);
		ready = 0;
		consumed++;
		pthread_mutex_unlock(&m);
	}
	return 0;
}
int main() {
	pthread_t c;
	if (pthread_create(&c, 0, consumer, 0) != 0) return 1;
	for (int i = 0; i < ITEMS; i++) {
		pthread_mutex_lock(&m);
		ready = 1;
		produced++;
		pthread_cond_signal(&cv);
		pthread_mutex_unlock(&m);
	}
	pthread_join(c, 0);
	return (produced == ITEMS && consumed == ITEMS) ? 666 : 2;
})M", "-pthread");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"threads"}, env);
	machine.run(3.0f); // deadlocks today; keep the !shouldfail wait short

	REQUIRE(machine.return_value() == 666);
}
