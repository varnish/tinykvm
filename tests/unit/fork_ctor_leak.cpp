#include <catch2/catch_test_macros.hpp>

#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <string>
#include <unistd.h>
#include <vector>
#include <tinykvm/machine.hpp>

/* The fork constructor acquires the vCPU fd and the vCPU's POSIX timer, and
   only *then* reaches steps that can throw -- setup_cow_mode() runs out of
   working memory being the documented one. ~Machine is never run for a
   constructor that threw, so anything the vCPU still holds at that point is
   leaked unless the vCPU itself releases it. That is what this file pins:
   a few thousand failing constructions must return the process to its
   starting fd count and its starting POSIX-timer count.

   Both counts are read out of /proc/self, which is where the leak is actually
   visible; and the loop is long enough that a leaked fd would blow the
   default RLIMIT_NOFILE (1024) on its own, turning the expected
   "Out of working memory" into a KVM_CREATE_VCPU failure -- so the exception
   *message* is asserted too, and stays a valid check on a host with a large
   fd limit where the counting alone would still pass. */

extern std::vector<uint8_t> build_and_load(const std::string& code);

static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const uint64_t MAX_COWMEM =  4ul << 20; /* 4MB */
/* Enough that a one-fd-per-iteration leak exhausts the default 1024-fd
   RLIMIT_NOFILE several times over, while still running in well under a
   second (no KVM_RUN happens on this path). */
static constexpr int FAILING_FORKS = 4000;
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

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

/* Every open fd of this process, KVM's or not: the leak is a vCPU fd, but
   counting all of them keeps the check honest about anything else the failed
   construction forgot to close. */
static size_t count_open_fds()
{
	DIR* dir = opendir("/proc/self/fd");
	REQUIRE(dir != nullptr);
	size_t count = 0;
	while (const struct dirent* entry = readdir(dir)) {
		if (entry->d_name[0] == '.')
			continue;
		count += 1;
	}
	closedir(dir);
	return count;
}

/* POSIX timers are not fds and do not show up above -- /proc/self/timers is
   the only place a timer_create() that was never timer_delete()d is visible.
   One "ID:" line per live timer. */
static size_t count_posix_timers()
{
	FILE* f = fopen("/proc/self/timers", "r");
	if (f == nullptr) {
		/* CONFIG_CHECKPOINT_RESTORE=n. The fd half still runs. */
		return SIZE_MAX;
	}
	size_t count = 0;
	char line[256];
	while (fgets(line, sizeof(line), f) != nullptr) {
		if (strncmp(line, "ID:", 3) == 0)
			count += 1;
	}
	fclose(f);
	return count;
}

/* A master parked at its entry point, forkable. Built once: the guest is
   irrelevant to this test -- no fork here ever runs -- and compiling it 4000
   times would dominate the runtime. */
static tinykvm::Machine& forkable_master()
{
	static std::vector<uint8_t> binary = build_and_load(R"M(
int main() { return 0; }
)M");
	static tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	static bool prepared = false;
	if (!prepared) {
		prepared = true;
		machine.setup_linux({"leak"}, env);
		machine.run(8.0f);
		machine.prepare_copy_on_write();
	}
	return machine;
}

/* max_cow_mem = 0 leaves the fork's memory banks with a ceiling of zero
   pages, so the very first new_page() in setup_cow_mode() throws -- which is
   after vCPU::init()/init_from_seat() has taken the fd and the timer, i.e.
   exactly the window this test is about. */
static tinykvm::MachineOptions failing_fork_options(bool pooled)
{
	tinykvm::MachineOptions options;
	options.max_mem = MAX_MEMORY;
	options.max_cow_mem = 0;
	options.vm_group = pooled;
	return options;
}

TEST_CASE("A throwing fork constructor leaks no vCPU fd or POSIX timer", "[fork][leak]")
{
	require_kvm();
	auto& master = forkable_master();
	REQUIRE(master.is_forkable());

	/* One throwing construction first, so any one-time allocation it makes
	   (the timer's signal handler, /proc opens, ...) is already accounted for
	   in the baseline and cannot be mistaken for a leak. */
	REQUIRE_THROWS(tinykvm::Machine{master, failing_fork_options(false)});

	const size_t fds_before = count_open_fds();
	const size_t timers_before = count_posix_timers();

	for (int i = 0; i < FAILING_FORKS; i++) {
		bool threw = false;
		try {
			tinykvm::Machine fork {master, failing_fork_options(false)};
			(void)fork;
		} catch (const tinykvm::MemoryException& e) {
			threw = true;
			/* Not "Failed to KVM_CREATE_VCPU"/"Unable to create timeout
			   timer": the fork must still be failing for the reason the test
			   arranged, not because a leak exhausted a limit. */
			REQUIRE(std::string(e.what()) == "Out of working memory");
		}
		REQUIRE(threw);
	}

	REQUIRE(count_open_fds() == fds_before);
	if (timers_before != SIZE_MAX) {
		REQUIRE(count_posix_timers() == timers_before);
	}
}

/* The pooled twin. A VM group seat owns its vCPU fd and its timer for the
   life of the group and hands them to each tenant in turn, so the release the
   test above demands must NOT happen here: a member whose constructor throws
   has to give the seat back intact. Both halves of that are checked -- no
   growth across the failing loop (the seat is returned, not burned), and a
   working fork afterwards (the fd was handed back, not closed). */
TEST_CASE("A throwing pooled fork constructor returns its seat intact", "[fork][leak][vm_group]")
{
	require_kvm();
	auto& master = forkable_master();
	REQUIRE(master.is_forkable());

	REQUIRE_THROWS(tinykvm::Machine{master, failing_fork_options(true)});

	const size_t fds_before = count_open_fds();
	const size_t timers_before = count_posix_timers();

	for (int i = 0; i < FAILING_FORKS; i++) {
		REQUIRE_THROWS(tinykvm::Machine{master, failing_fork_options(true)});
	}

	REQUIRE(count_open_fds() == fds_before);
	if (timers_before != SIZE_MAX) {
		REQUIRE(count_posix_timers() == timers_before);
	}

	/* The seat survived every failure: it can still be taken and used. */
	tinykvm::MachineOptions good = failing_fork_options(true);
	good.max_cow_mem = MAX_COWMEM;
	tinykvm::Machine fork {master, good};
	REQUIRE(fork.is_forked());
}
