#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/paging.hpp>
#include <tinykvm/smp.hpp>
#include <tinykvm/amd64/amd64.hpp>
#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <stdexcept>
#include <string>
#include <sys/mman.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const uint64_t MAX_COWMEM = 3ul << 20; /* 3MB */
static constexpr uint32_t GROUP_SIZE = 4;
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

/* Every struct kvm is one open fd symlinking to anon_inode:kvm-vm, and one
   registration on the host-global PM-notifier chain. With pooling there must
   be one for each *group*, not one for each fork. This is the check that
   proves pooling engaged at all — the counting equivalent of lazy_kvm_run's
   count_vcpu_mappings(). */
static size_t count_kvm_vms()
{
	DIR* dir = opendir("/proc/self/fd");
	REQUIRE(dir != nullptr);
	size_t count = 0;
	while (const struct dirent* entry = readdir(dir)) {
		if (entry->d_name[0] == '.')
			continue;
		char path[64];
		char link[256];
		snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
		const ssize_t len = readlink(path, link, sizeof(link) - 1);
		if (len <= 0)
			continue;
		link[len] = 0;
		/* NB: a vCPU is anon_inode:kvm-vcpu:N, which does not match. */
		if (strstr(link, "kvm-vm") != nullptr)
			count += 1;
	}
	closedir(dir);
	return count;
}

/* Seats hold their vCPU fds for the lifetime of the group -- a struct kvm never
   reclaims vCPU capacity, so a member handing its seat back must not close the
   fd. Whole-group retirement is the one place they may be closed, and this is
   how that is checked. */
static size_t count_kvm_vcpus()
{
	DIR* dir = opendir("/proc/self/fd");
	REQUIRE(dir != nullptr);
	size_t count = 0;
	while (const struct dirent* entry = readdir(dir)) {
		if (entry->d_name[0] == '.')
			continue;
		char path[64];
		char link[256];
		snprintf(path, sizeof(path), "/proc/self/fd/%s", entry->d_name);
		const ssize_t len = readlink(path, link, sizeof(link) - 1);
		if (len <= 0)
			continue;
		link[len] = 0;
		if (strstr(link, "kvm-vcpu") != nullptr)
			count += 1;
	}
	closedir(dir);
	return count;
}

/* One mmap'ed kvm_run page per vCPU that has ever run (lever C). Pooling does
   not change that: the mapping belongs to the seat. */
static size_t count_vcpu_mappings()
{
	FILE* f = fopen("/proc/self/maps", "r");
	REQUIRE(f != nullptr);
	size_t count = 0;
	char line[512];
	while (fgets(line, sizeof(line), f) != nullptr) {
		if (strstr(line, "anon_inode:kvm-vcpu") != nullptr)
			count += 1;
	}
	fclose(f);
	return count;
}

/* The permission field of the /proc/self/maps region holding @addr, or an
   empty string when the address is not mapped at all. Used to prove that a
   seat's guard band is reserved *and* inaccessible in the host address
   space, not merely absent from the seat's memslot. */
static std::string maps_perms_at(const void* addr)
{
	const unsigned long needle = (unsigned long) addr;
	FILE* f = fopen("/proc/self/maps", "r");
	REQUIRE(f != nullptr);
	char line[512];
	std::string result;
	while (fgets(line, sizeof(line), f) != nullptr) {
		unsigned long begin = 0, end = 0;
		char perms[8] = {0};
		if (sscanf(line, "%lx-%lx %7s", &begin, &end, perms) != 3)
			continue;
		if (needle >= begin && needle < end) {
			result = perms;
			break;
		}
	}
	fclose(f);
	return result;
}

/* Every VMA in this process. This is the number the group window exists to keep
   flat in the number of seats: mm_take_all_locks() walks and write-locks every
   one of them on every later KVM_CREATE_VM, and each mmap()/mprotect() that
   creates or splits one takes the mmap_lock for writing. */
static size_t count_vmas()
{
	FILE* f = fopen("/proc/self/maps", "r");
	REQUIRE(f != nullptr);
	size_t count = 0;
	char line[512];
	while (fgets(line, sizeof(line), f) != nullptr) {
		/* A line longer than the buffer arrives as several fgets: count only
		   the piece that ends it, so one VMA is always one count. */
		if (strchr(line, '\n') != nullptr)
			count += 1;
	}
	fclose(f);
	return count;
}

/* The VMAs overlapping [begin, begin+len) -- i.e. a group window's own share of
   the count above. Process-wide counting states the claim that matters ("a seat
   costs the process nothing"), but it also moves when the test binary's heap
   grows or when two unrelated mappings coalesce; this states the geometry of one
   window exactly, and is what distinguishes the three guard modes. */
static size_t count_vmas_in(const char* begin, uint64_t len)
{
	const unsigned long lo = (unsigned long) begin;
	const unsigned long hi = lo + len;
	FILE* f = fopen("/proc/self/maps", "r");
	REQUIRE(f != nullptr);
	size_t count = 0;
	char line[512];
	while (fgets(line, sizeof(line), f) != nullptr) {
		unsigned long b = 0, e = 0;
		if (sscanf(line, "%lx-%lx ", &b, &e) != 2)
			continue;
		if (b < hi && e > lo)
			count += 1;
	}
	fclose(f);
	return count;
}

/* Write a byte through @addr in a child process; returns 0 if the child exited
   cleanly, or the signal that killed it.

   fork() from a test that holds live KVM fds is safe for this: the child
   touches one address and leaves through _exit(), so it runs no atexit handler,
   never flushes Catch2's reporter, and issues no ioctl on the inherited fds.
   The buffers are flushed before forking so the child has nothing of ours to
   duplicate, and the store goes through a volatile pointer so it cannot be
   optimised away. */
static int probe_write_in_child(volatile char* addr)
{
	fflush(nullptr);
	const pid_t pid = fork();
	REQUIRE(pid >= 0);
	if (pid == 0) {
		*addr = 0x5A;
		_exit(0);
	}
	int status = 0;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	if (WIFSIGNALED(status))
		return WTERMSIG(status);
	REQUIRE(WIFEXITED(status));
	return -WEXITSTATUS(status);
}

static tinykvm::MachineOptions pooled_options()
{
	tinykvm::MachineOptions options;
	options.max_mem = MAX_MEMORY;
	options.max_cow_mem = MAX_COWMEM;
	options.vm_group = true;
	options.vm_group_size = GROUP_SIZE;
	return options;
}

/* Pooled options with the host guard mode pinned. Every test that counts VMAs
   or reads /proc/self/maps uses this rather than the default: Auto resolves from
   the kernel version and the build's NDEBUG, so a test that let it decide would
   assert a different layout on a 6.13 box or in a release build.

   lazy_vcpu_mmap comes with it, because the seat's kvm_run page is the other
   thing that costs a VMA per seat. Lazy means a member that never enters the
   guest maps nothing, so "flat in the number of seats" can be asserted exactly
   rather than modulo one mapping per member that happened to run. */
static tinykvm::MachineOptions pooled_options(tinykvm::VmGroupHostGuard guard)
{
	auto options = pooled_options();
	options.vm_group_host_guard = guard;
	options.lazy_vcpu_mmap = true;
	return options;
}

/* Pooled options with the arena slot mode pinned. Everything about the guard
   bands - whether a guest touching one faults at all, and whether the host can
   see what it wrote - is a function of this and of the guard mode together
   (see VmGroupArenaSlot), so a test that states either has to pin both rather
   than inherit the build's TINYKVM_VM_GROUP_ARENA_SLOT_DEFAULT. */
static tinykvm::MachineOptions pooled_options(tinykvm::VmGroupArenaSlot slot)
{
	auto options = pooled_options();
	options.vm_group_arena_slot = slot;
	return options;
}
static tinykvm::MachineOptions pooled_options(tinykvm::VmGroupHostGuard guard,
	tinykvm::VmGroupArenaSlot slot)
{
	auto options = pooled_options(guard);
	options.vm_group_arena_slot = slot;
	return options;
}

static tinykvm::MachineOptions solo_options()
{
	tinykvm::MachineOptions options = pooled_options();
	options.vm_group = false;
	options.vm_group_size = 0;
	return options;
}

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

static std::vector<uint8_t> group_test_binary()
{
	return build_and_load(R"M(
int main() {
}

static int value = 0;
extern int get_value() {
	value ++;
	return value;
}
extern int set_value(int v) {
	value = v;
	return value;
}
extern int read_value() {
	return value;
}
extern void spin_forever() {
	while (1) __asm__ volatile("");
}
/* Write through an arbitrary guest *virtual* address and read it back. Used with
   a poked page-table entry, which is the only way a guest can be made to touch a
   guest-physical address the loader never mapped - such as a guard band. */
extern int touch_at(unsigned long addr, int value) {
	volatile int* p = (volatile int*) addr;
	*p = value;
	return *p;
}
/* Leave a recognisable pattern in the SSE register file, and leave it there
   across the return to the park point: the vCPU fd (and its xsave area) is
   what the next tenant of this seat inherits. */
extern void dirty_fpu(unsigned long pattern) {
	__asm__ volatile(
		"movq %0, %%xmm0\n"
		"movq %0, %%xmm3\n"
		"movq %0, %%xmm7\n"
		"movq %0, %%xmm15\n"
		:: "r"(pattern)
		: "xmm0", "xmm3", "xmm7", "xmm15");
})M");
}

TEST_CASE("KVM limits are queried once", "[VmGroup]")
{
	const auto& limits = tinykvm::KvmLimits::get();
	/* The count of vCPUs a struct kvm can hold is what bounds a group. */
	REQUIRE(limits.max_vcpus > 0);
	REQUIRE(limits.max_vcpu_id >= limits.max_vcpus);
	REQUIRE(limits.nr_memslots > 0);
	REQUIRE(limits.vcpu_mmap_size > 0);
}

TEST_CASE("Pooled forks share one VM per group", "[VmGroup]")
{
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_kvm_vms();
	REQUIRE(baseline > 0);

	/* B+2 members of one master: ceil((B+2)/B) = 2 groups, not B+2 VMs. */
	static constexpr size_t MEMBERS = GROUP_SIZE + 2;
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (size_t i = 0; i < MEMBERS; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
			REQUIRE(forks.back()->is_pooled());
			REQUIRE(forks.back()->is_forked());
			/* Every member's main vCPU is guest CPU 0; only the
			   KVM_CREATE_VCPU id is group-unique. */
			REQUIRE(forks.back()->cpu().guest_cpu_index == 0);
		}
		REQUIRE(count_kvm_vms() == baseline + 2);

		REQUIRE(forks[0]->group() != forks[GROUP_SIZE]->group());
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			REQUIRE(forks[i]->group() == forks[0]->group());
			REQUIRE(forks[i]->cpu().kvm_vcpu_id == int(i));
		}
		REQUIRE(forks[0]->group()->capacity() == GROUP_SIZE);
		REQUIRE(forks[0]->group()->live_members() == GROUP_SIZE);
		REQUIRE(machine.groups().group_count() == 2);
	}
	/* The forks are destroyed in order, so group 1's four members go first,
	   emptying it - and it is kept, as the warm spare. Then group 2 empties too,
	   at which point there are two empty eligible groups and only one spare:
	   group 2 just emptied so it keeps it, and group 1 is retired and its struct
	   kvm closed. See the policy note on VmGroupSet::note_seat_released(). */
	REQUIRE(count_kvm_vms() == baseline + 1);
	REQUIRE(machine.groups().group_count() == 1);
}

TEST_CASE("Unpooled forks create one VM each", "[VmGroup]")
{
	/* Control for the counting above: without the option, every fork creates
	   its own struct kvm. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_kvm_vms();
	static constexpr size_t MEMBERS = GROUP_SIZE + 2;
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (size_t i = 0; i < MEMBERS; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, solo_options()));
			REQUIRE(!forks.back()->is_pooled());
		}
		REQUIRE(count_kvm_vms() == baseline + MEMBERS);
	}
	REQUIRE(count_kvm_vms() == baseline);
}

TEST_CASE("Pooled forks run independently", "[VmGroup]")
{
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	const auto set_value = machine.address_of("set_value");
	const auto read_value = machine.address_of("read_value");
	REQUIRE(get_value != 0x0);
	REQUIRE(set_value != 0x0);
	REQUIRE(read_value != 0x0);

	static constexpr size_t MEMBERS = 2 * GROUP_SIZE;
	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < MEMBERS; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
	}

	/* Each member starts from the master's state, in its own partition. */
	for (size_t i = 0; i < MEMBERS; i++) {
		forks[i]->timed_vmcall(get_value, 4.0f);
		REQUIRE(forks[i]->return_value() == 1);
		REQUIRE(forks[i]->banked_memory_pages() > 0);
	}

	/* Distinct markers written through CoW'ed guest memory. */
	for (size_t i = 0; i < MEMBERS; i++) {
		forks[i]->timed_vmcall(set_value, 4.0f, int(100 + i));
		REQUIRE(forks[i]->return_value() == long(100 + i));
	}
	/* Siblings sharing a struct kvm must not see each other's writes. */
	for (size_t i = 0; i < MEMBERS; i++) {
		forks[i]->timed_vmcall(read_value, 4.0f);
		REQUIRE(forks[i]->return_value() == long(100 + i));
	}

	/* The master is untouched by any of it. */
	machine.timed_vmcall(read_value, 4.0f);
	REQUIRE(machine.return_value() == 0);
}

TEST_CASE("Pooled arena partitions are strided", "[VmGroup]")
{
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const uint64_t master_arena = machine.main_memory().banks.arena_begin();

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
	}

	const auto* group = forks[0]->group();
	REQUIRE(group != nullptr);
	/* Stride = the working-memory ceiling rounded up to a whole bank, plus
	   one unmapped bank of guard band. */
	const uint64_t stride = group->arena_stride();
	REQUIRE(stride == tinykvm::VmGroup::BANK_ALIGNMENT + tinykvm::VmGroup::GUARD_BAND);
	REQUIRE(group->arena_base() == master_arena);

	for (size_t i = 0; i < GROUP_SIZE; i++) {
		const auto& banks = forks[i]->main_memory().banks;
		REQUIRE(banks.is_partitioned());
		REQUIRE(banks.arena_begin() == master_arena + i * stride);
		const auto* seat = forks[i]->seat();
		REQUIRE(seat != nullptr);
		REQUIRE(seat->arena_gpa == banks.arena_begin());
		REQUIRE(seat->arena_size == stride - tinykvm::VmGroup::GUARD_BAND);
	}
	for (size_t i = 1; i < GROUP_SIZE; i++) {
		REQUIRE(forks[i]->main_memory().banks.arena_begin()
			- forks[i - 1]->main_memory().banks.arena_begin() == stride);
	}
}

TEST_CASE("Pooled seats are handed back, not burned", "[VmGroup]")
{
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_kvm_vms();
	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	/* 3B members serially through a B-seat group: seats are reused (their
	   vCPU capacity is consumed permanently, see the group's contract), so
	   no second group appears and every member behaves identically.

	   Each member here is the group's only one, so the group is empty between
	   iterations - and stays alive, because retirement never takes the last
	   group of a master: doing so would pay a KVM_CREATE_VM (and destroy) per
	   fork at low occupancy, which is the exact cost pooling exists to remove.
	   That is also what keeps seat 0 warm, so high_water() stays at 1. */
	for (size_t i = 0; i < 3 * GROUP_SIZE; i++) {
		tinykvm::Machine fork { machine, pooled_options() };
		fork.timed_vmcall(get_value, 4.0f);
		REQUIRE(fork.return_value() == 1);
		REQUIRE(fork.group()->high_water() == 1);
		REQUIRE(count_kvm_vms() == baseline + 1);
	}
	REQUIRE(machine.groups().group_count() == 1);
}

TEST_CASE("Pooled forks work with a lazily mapped kvm_run", "[VmGroup]")
{
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t vcpu_baseline = count_vcpu_mappings();
	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	auto options = pooled_options();
	options.lazy_vcpu_mmap = true;

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	}
	/* Parked pooled members map nothing. */
	REQUIRE(count_vcpu_mappings() == vcpu_baseline);

	forks[0]->timed_vmcall(get_value, 4.0f);
	REQUIRE(forks[0]->return_value() == 1);
	forks[1]->timed_vmcall(get_value, 4.0f);
	REQUIRE(forks[1]->return_value() == 1);
	REQUIRE(count_vcpu_mappings() == vcpu_baseline + 2);

	/* The mapping belongs to the seat, so the next tenant of that seat
	   inherits it and does not pay the flip again. */
	const void* seat0_kvm_run = forks[0]->seat()->kvm_run;
	REQUIRE(seat0_kvm_run != nullptr);
	forks[0].reset();

	tinykvm::Machine reused { machine, options };
	REQUIRE(reused.seat()->kvm_run == seat0_kvm_run);
	reused.timed_vmcall(get_value, 4.0f);
	REQUIRE(reused.return_value() == 1);
	REQUIRE(count_vcpu_mappings() == vcpu_baseline + 2);

	/* A never-run seat still hands out an unmapped one. */
	forks.clear();
	tinykvm::Machine parked { machine, options };
	REQUIRE(parked.seat()->kvm_run == nullptr);
	REQUIRE(count_vcpu_mappings() == vcpu_baseline + 2);
}

TEST_CASE("VM group refusals", "[VmGroup]")
{
	const auto binary = group_test_binary();

	SECTION("A master ignores the pooling flag (lazy_vcpu_mmap-style)") {
		tinykvm::MachineOptions options;
		options.max_mem = MAX_MEMORY;
		options.vm_group = true;
		tinykvm::Machine master { binary, options };
		REQUIRE(!master.is_pooled());
	}

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	SECTION("Pooled forks cannot swap main memory") {
		auto options = pooled_options();
		options.allow_reset_to_new_master = true;
		REQUIRE_THROWS_AS(
			(tinykvm::Machine{machine, options}), tinykvm::MachineException);
	}
	SECTION("Pooled forks cannot use hugepages") {
		auto options = pooled_options();
		options.hugepages = true;
		REQUIRE_THROWS_AS(
			(tinykvm::Machine{machine, options}), tinykvm::MachineException);

		options = pooled_options();
		options.hugepages_arena_size = 2ul << 20;
		REQUIRE_THROWS_AS(
			(tinykvm::Machine{machine, options}), tinykvm::MachineException);
	}
	SECTION("Pooled forks cannot create mmap-backed areas") {
		tinykvm::Machine fork { machine, pooled_options() };
		REQUIRE_THROWS_AS(
			fork.mmap_backed_area(0, 0, 0x3, 0x40000000, 4096),
			tinykvm::MachineException);
	}
	SECTION("Pooled forks cannot write the shared vCPU table") {
		tinykvm::Machine fork { machine, pooled_options() };
		REQUIRE_THROWS_AS(
			fork.cpu().set_vcpu_table_at(1, 42), tinykvm::MachineException);
	}
}

TEST_CASE("A pooled reset cannot raise the working-memory ceiling", "[VmGroup]")
{
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	tinykvm::Machine fork { machine, pooled_options() };
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);

	/* The arena stays inside the partition, whose end is a hard wall in
	   MemoryBanks::allocate_new_bank() and can only be reached by raising
	   the budget the partition was sized from. */
	REQUIRE(fork.main_memory().banks.partition_used() > 0);
	REQUIRE(fork.main_memory().banks.partition_used() <= fork.seat()->arena_size);

	/* Resetting with the same budget is the hot path. */
	fork.reset_to(machine, pooled_options());
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);

	auto bigger = pooled_options();
	bigger.max_cow_mem = 64ul << 20;
	REQUIRE_THROWS_AS(fork.reset_to(machine, bigger), tinykvm::MemoryException);
}

TEST_CASE("A larger working-memory budget opens a new group", "[VmGroup]")
{
	/* The group's ceiling is frozen at creation, so a member that needs more
	   than it cannot ever be built into that group. Refusing such a member
	   would be a *permanent* create_fork() outage for this master: the group
	   is never full, so no new group would ever be opened and every fork with
	   the larger budget would throw forever. Group eligibility, not just free
	   capacity, is what decides. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	auto small = pooled_options();
	small.max_cow_mem = 2ul << 20;
	auto large = pooled_options();
	large.max_cow_mem = 24ul << 20;

	tinykvm::Machine first { machine, small };
	first.timed_vmcall(get_value, 4.0f);
	REQUIRE(first.return_value() == 1);
	REQUIRE(machine.groups().group_count() == 1);
	REQUIRE(first.group()->live_members() == 1);

	tinykvm::Machine second { machine, large };
	second.timed_vmcall(get_value, 4.0f);
	REQUIRE(second.return_value() == 1);
	REQUIRE(machine.groups().group_count() == 2);
	REQUIRE(second.group() != first.group());
	/* The new group's ceiling froze at the larger budget, and its stride
	   grew with it. */
	REQUIRE(second.group()->max_cow_mem() == large.max_cow_mem);
	REQUIRE(second.group()->arena_stride() > first.group()->arena_stride());
	/* The small group is untouched and still has room. */
	REQUIRE(first.group()->live_members() == 1);

	/* And it is still the one a small member lands in. */
	tinykvm::Machine third { machine, small };
	REQUIRE(third.group() == first.group());
	REQUIRE(machine.groups().group_count() == 2);

	/* A second large member reuses the large group rather than opening a
	   third: the eligibility test is "at least", not "equal to". */
	tinykvm::Machine fourth { machine, large };
	REQUIRE(fourth.group() == second.group());
	REQUIRE(machine.groups().group_count() == 2);
}

TEST_CASE("A seat's guard band is unmapped on the host side too", "[VmGroup]")
{
	/* Seat windows are adjacent in the host address space, so a host-side linear
	   overrun (page_duplicate() or a memcpy() walking off the end of the last
	   bank) would otherwise land silently in a sibling's guest memory - where an
	   unpooled VM's standalone bank mmap would have SIGSEGV'd. The stride is
	   reserved whole and only the usable part is made accessible.

	   Mode caveat: this is the *host* side of the band only, and it holds
	   because the default guard mode resolves to Mprotect in a debug build on a
	   pre-6.13 kernel - which is what pooled_options() gets here (Auto). The
	   pinned-mode statements are "The mprotect guard mode carves a PROT_NONE
	   band per seat" and "The off guard mode leaves the whole stride
	   accessible"; what a *guest* touching the band sees is a function of the
	   arena slot mode too, and lives in "A guest touch of a guard band". */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	tinykvm::Machine fork { machine, pooled_options() };
	const auto* seat = fork.seat();
	REQUIRE(seat != nullptr);
	REQUIRE(seat->arena_hva != nullptr);

	REQUIRE(maps_perms_at(seat->arena_hva) == "rw-p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size - 1) == "rw-p");
	/* The guard band: reserved (so nothing else can be mapped into it) and
	   inaccessible for its whole length. */
	const uint64_t guard = fork.group()->arena_stride() - seat->arena_size;
	REQUIRE(guard == tinykvm::VmGroup::GUARD_BAND);
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size) == "---p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size + guard - 1) == "---p");
}

TEST_CASE("The arena span bounds the group size", "[VmGroup]")
{
	/* Pooling multiplies the arena by B, so a working-memory budget that is
	   unremarkable for one VM can walk the span out of the arena's range in
	   guest-physical space. The span is a wall on B, alongside the vCPU
	   count wall. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	auto options = pooled_options();
	options.max_cow_mem = 1024ul << 20; /* 1GB: a 1032MB stride */
	options.vm_group_size = 4096;

	tinykvm::Machine fork { machine, options };
	const auto* group = fork.group();
	const uint64_t stride = group->arena_stride();
	REQUIRE(group->capacity() < options.vm_group_size);
	REQUIRE(group->capacity() == tinykvm::VmGroup::ARENA_SPAN_LIMIT / stride);
	/* Whatever B ended up being, the span stays inside the arena's range. */
	REQUIRE(uint64_t(group->capacity()) * stride <= tinykvm::VmGroup::ARENA_SPAN_LIMIT);
	REQUIRE(group->arena_base() + uint64_t(group->capacity()) * stride
		<= tinykvm::MemoryBanks::ARENA_BASE_ADDRESS + tinykvm::VmGroup::ARENA_SPAN_LIMIT);

	/* I1: the host reservation is byte-for-byte the guest-physical span, so the
	   same wall bounds both. This is the case where it matters - a 1032 MiB
	   stride puts the reservation in the tens of gigabytes of address space, and
	   ARENA_SPAN_LIMIT is what keeps it finite. */
	REQUIRE(group->arena_span() == uint64_t(group->capacity()) * stride);
	REQUIRE(group->arena_span() <= tinykvm::VmGroup::ARENA_SPAN_LIMIT);
	REQUIRE(group->arena_hva() != nullptr);
}

TEST_CASE("A seat reused from another thread rebinds its timer", "[VmGroup]")
{
	/* A seat's POSIX timer is bound to the thread that created it
	   (SIGEV_THREAD_ID with sigev_tid), but the seat itself is not
	   thread-bound. Adopting the timer as-is breaks two ways at once: the new
	   tenant's execution timeout never interrupts its KVM_RUN, so an infinite
	   guest loop hangs forever; and the 20ms re-arm interval keeps firing at
	   the *original* thread, setting its thread_local timer_was_triggered and
	   timing out whichever innocent sibling is running there. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	const auto spin_forever = machine.address_of("spin_forever");
	REQUIRE(get_value != 0x0);
	REQUIRE(spin_forever != 0x0);

	/* 0: thread A materializes seat 0 and hands it back.
	   1: this thread adopts seat 0 and spins in the guest.
	   2: thread A runs finite calls on a seat of its own, alongside it.
	   3: done. NB: no Catch2 assertions on thread A - they are not
	   thread-safe. Failures come back as an exception_ptr. */
	std::atomic<int> phase {0};
	std::atomic<unsigned> a_calls {0};
	std::exception_ptr a_error;

	std::thread a([&] {
		try {
			{
				tinykvm::Machine fork { machine, pooled_options() };
				fork.timed_vmcall(get_value, 4.0f);
				if (fork.return_value() != 1)
					throw std::runtime_error("A: unexpected return value");
				if (fork.seat()->kvm_vcpu_id != 0)
					throw std::runtime_error("A: did not materialize seat 0");
			}
			phase = 1;
			while (phase.load() < 2)
				std::this_thread::yield();
			/* A sibling on the timer's original thread. Every one of these
			   runs is finite and must complete: a stray interval signal
			   arriving here would abort one of them with a timeout. */
			tinykvm::Machine sibling { machine, pooled_options() };
			while (phase.load() < 3) {
				sibling.timed_vmcall(get_value, 4.0f);
				a_calls += 1;
			}
		} catch (...) {
			a_error = std::current_exception();
		}
		phase = 3;
	});

	while (phase.load() == 0)
		std::this_thread::yield();

	if (!a_error) {
		/* Seat 0 is the only free seat, so this thread deterministically
		   adopts the seat whose timer belongs to thread A. */
		tinykvm::Machine fork { machine, pooled_options() };
		REQUIRE(fork.seat()->kvm_vcpu_id == 0);
		REQUIRE(fork.group()->high_water() == 1);
		phase = 2;
		REQUIRE_THROWS_AS(fork.timed_vmcall(spin_forever, 0.25f),
			tinykvm::MachineTimeoutException);
	}
	phase = 3;
	a.join();
	if (a_error)
		std::rethrow_exception(a_error);
	REQUIRE(a_calls.load() > 0);

	/* And the seat is still usable afterwards, from this thread. */
	tinykvm::Machine after { machine, pooled_options() };
	after.timed_vmcall(get_value, 4.0f);
	REQUIRE(after.return_value() == 1);
}

TEST_CASE("Empty VM groups are retired down to one warm spare", "[VmGroup]")
{
	/* Plan test 6, plus the hysteresis the first cut of it lacked. Retirement
	   meshes with build-into-the-emptiest-group: a group whose seats are all
	   free is genuinely idle, so its struct kvm (one PM-notifier registration,
	   one mm_take_all_locks worth of teardown) can go back to the host. But
	   retiring *every* empty group makes occupancy that straddles a group
	   boundary pay a KVM_CREATE_VM and a teardown per fork, synchronously in
	   ~Machine -- so one empty eligible group is kept as a warm spare. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_kvm_vms();
	const size_t vcpu_baseline = count_kvm_vcpus();
	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	SECTION("The group that just emptied is kept, and refilled") {
		/* Fill one group to capacity. */
		std::vector<std::unique_ptr<tinykvm::Machine>> first;
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			first.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
			first.back()->timed_vmcall(get_value, 4.0f);
			REQUIRE(first.back()->return_value() == 1);
		}
		REQUIRE(machine.groups().group_count() == 1);
		REQUIRE(count_kvm_vms() == baseline + 1);
		REQUIRE(count_kvm_vcpus() == vcpu_baseline + GROUP_SIZE);
		const auto* group_one = first[0]->group();
		REQUIRE(group_one->live_members() == GROUP_SIZE);
		const uint32_t group_one_id = group_one->id();

		/* One more than capacity: a second group appears. */
		tinykvm::Machine overflow { machine, pooled_options() };
		overflow.timed_vmcall(get_value, 4.0f);
		REQUIRE(overflow.return_value() == 1);
		REQUIRE(machine.groups().group_count() == 2);
		REQUIRE(overflow.group() != group_one);
		REQUIRE(count_kvm_vms() == baseline + 2);

		/* Drain group 1 completely. It is empty and still eligible, so it is
		   kept as the warm spare rather than retired: nothing is closed, and
		   its four seats keep their vCPUs (capacity a struct kvm never gives
		   back) ready for the next member. */
		first.clear();
		REQUIRE(group_one->live_members() == 0);
		REQUIRE(machine.groups().group_count() == 2);
		REQUIRE(count_kvm_vms() == baseline + 2);
		REQUIRE(count_kvm_vcpus() == vcpu_baseline + GROUP_SIZE + 1);

		/* And it is what the next member joins - the emptiest eligible group -
		   on a seat that already exists. */
		tinykvm::Machine rejoin { machine, pooled_options() };
		REQUIRE(rejoin.group() == group_one);
		REQUIRE(rejoin.group()->id() == group_one_id);
		REQUIRE(rejoin.group()->high_water() == GROUP_SIZE);
		rejoin.timed_vmcall(get_value, 4.0f);
		REQUIRE(rejoin.return_value() == 1);
		REQUIRE(count_kvm_vms() == baseline + 2);
	}

	SECTION("Empty eligible groups beyond the spare are retired") {
		/* Three groups: two full, one with a single member. */
		std::vector<std::unique_ptr<tinykvm::Machine>> members;
		for (size_t i = 0; i < 2 * GROUP_SIZE + 1; i++) {
			members.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
			members.back()->timed_vmcall(get_value, 4.0f);
		}
		REQUIRE(machine.groups().group_count() == 3);
		REQUIRE(count_kvm_vms() == baseline + 3);
		const auto* group_one = members[0]->group();
		const auto* group_two = members[GROUP_SIZE]->group();
		const auto* group_three = members[2 * GROUP_SIZE]->group();
		REQUIRE(group_one != group_two);
		REQUIRE(group_two != group_three);
		char* const g2_seat0_hva = members[GROUP_SIZE]->seat()->arena_hva;
		REQUIRE(maps_perms_at(g2_seat0_hva) == "rw-p");

		/* Empty group 2: it becomes the spare. */
		for (size_t i = GROUP_SIZE; i < 2 * GROUP_SIZE; i++) {
			members[i].reset();
		}
		REQUIRE(group_two->live_members() == 0);
		REQUIRE(machine.groups().group_count() == 3);

		/* Now empty group 1 too. Two empty eligible groups, one spare: the one
		   that just emptied keeps it, and group 2 is retired - VM fd, seat vCPU
		   fds and arena windows all released. */
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			members[i].reset();
		}
		REQUIRE(group_one->live_members() == 0);
		REQUIRE(machine.groups().group_count() == 2);
		REQUIRE(count_kvm_vms() == baseline + 2);
		REQUIRE(count_kvm_vcpus() == vcpu_baseline + GROUP_SIZE + 1);
		REQUIRE(maps_perms_at(g2_seat0_hva) == "");
		const auto live = machine.groups().groups();
		REQUIRE(live.size() == 2);
		REQUIRE(((live[0].get() == group_one && live[1].get() == group_three)
			|| (live[0].get() == group_three && live[1].get() == group_one)));
	}

	SECTION("An empty group that can never serve anyone again is retired at once") {
		/* The reason the spare has to be chosen by eligibility and not by
		   "whichever emptied first": a group whose frozen working-memory ceiling
		   is below what this master's forks now ask for can never be built into
		   again, so keeping it resident both wastes a struct kvm and leaves the
		   group that *is* being used to be created and destroyed on every fork. */
		auto small = pooled_options();
		small.max_cow_mem = 2ul << 20;
		auto large = pooled_options();
		large.max_cow_mem = 24ul << 20;

		{
			tinykvm::Machine tiny { machine, small };
			tiny.timed_vmcall(get_value, 4.0f);
			REQUIRE(tiny.return_value() == 1);
		}
		/* The small group is empty, and still eligible: it is the spare. */
		REQUIRE(machine.groups().group_count() == 1);
		REQUIRE(count_kvm_vms() == baseline + 1);
		const auto* small_group = machine.groups().groups().at(0).get();

		/* A larger budget cannot be built into it, so a second group opens. */
		{
			tinykvm::Machine big { machine, large };
			big.timed_vmcall(get_value, 4.0f);
			REQUIRE(big.return_value() == 1);
			REQUIRE(big.group() != small_group);
			REQUIRE(machine.groups().group_count() == 2);
			REQUIRE(count_kvm_vms() == baseline + 2);
		}
		/* On the release, the small group is empty *and* ineligible for what
		   this master is asking for, so it goes; the large one just emptied and
		   is eligible, so it stays as the spare. */
		REQUIRE(machine.groups().group_count() == 1);
		REQUIRE(count_kvm_vms() == baseline + 1);
		REQUIRE(machine.groups().groups().at(0).get() != small_group);
		REQUIRE(machine.groups().groups().at(0)->max_cow_mem() == large.max_cow_mem);

		/* And the surviving group is the one the next large fork joins, with no
		   create/destroy at all. */
		tinykvm::Machine again { machine, large };
		REQUIRE(again.group() == machine.groups().groups().at(0).get());
		REQUIRE(count_kvm_vms() == baseline + 1);
	}
}

TEST_CASE("Occupancy straddling a group boundary creates no VMs", "[VmGroup]")
{
	/* The hysteresis, stated as a behavioural invariant rather than a timing
	   one. B live members plus one that is forked and destroyed over and over is
	   the worst case for retirement: the B+1st always lands in a second group
	   and always empties it. Without a warm spare that is a KVM_CREATE_VM and a
	   full teardown per iteration, paid synchronously in ~Machine on whatever
	   thread the request is on - measured at 11,185 us/iteration versus 377
	   us/iteration with no retirement at all, i.e. the whole pooling win
	   inverted. With the spare, the second group is created once and then simply
	   refilled: same group object, same id, same seat, no VM churn. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	std::vector<std::unique_ptr<tinykvm::Machine>> held;
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		held.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
		held.back()->timed_vmcall(get_value, 4.0f);
	}
	REQUIRE(machine.groups().group_count() == 1);
	const size_t vms_after_fill = count_kvm_vms();

	uint32_t straddler_group_id = 0;
	for (size_t i = 0; i < 32; i++) {
		tinykvm::Machine straddler { machine, pooled_options() };
		straddler.timed_vmcall(get_value, 4.0f);
		REQUIRE(straddler.return_value() == 1);
		REQUIRE(straddler.group() != held[0]->group());
		if (i == 0) {
			straddler_group_id = straddler.group()->id();
			/* Exactly one new struct kvm, on the first iteration only. */
			REQUIRE(count_kvm_vms() == vms_after_fill + 1);
		} else {
			/* The same group, refilled: no VM was created or destroyed, and the
			   seat it gets is one that already existed. */
			REQUIRE(straddler.group()->id() == straddler_group_id);
			REQUIRE(straddler.group()->high_water() == 1);
			REQUIRE(count_kvm_vms() == vms_after_fill + 1);
		}
		REQUIRE(machine.groups().group_count() == 2);
	}
	/* And the group id counter is global and monotonic, so this also proves no
	   group was constructed in between. */
	REQUIRE(machine.groups().groups().at(1)->id() == straddler_group_id);
}

/* Hidden (leading-dot tag): a timing probe, not an assertion. Run manually with
   `./vm_group "[straddle-probe]"`. Reports the cost of the boundary-straddling
   fork+destroy loop above, against an unpooled control, so the hysteresis can
   be re-measured after changes to the retirement policy. */
TEST_CASE("PROBE: boundary-straddling fork cost", "[.][straddle-probe]")
{
	tinykvm::Machine::init(); /* the [Initialize] case is filtered out here */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);
	const auto get_value = machine.address_of("get_value");

	static constexpr size_t ITERS = 200;
	const auto measure = [&] (const char* label, const tinykvm::MachineOptions& opts) {
		std::vector<std::unique_ptr<tinykvm::Machine>> held;
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			held.push_back(std::make_unique<tinykvm::Machine> (machine, opts));
			held.back()->timed_vmcall(get_value, 4.0f);
		}
		const auto t0 = std::chrono::steady_clock::now();
		for (size_t i = 0; i < ITERS; i++) {
			tinykvm::Machine straddler { machine, opts };
			straddler.timed_vmcall(get_value, 4.0f);
		}
		const auto t1 = std::chrono::steady_clock::now();
		const double us =
			std::chrono::duration<double, std::micro>(t1 - t0).count() / ITERS;
		printf("PROBE %-28s %9.1f us/iter (B=%u, %zu iters)\n",
			label, us, GROUP_SIZE, ITERS);
		fflush(stdout);
	};
	measure("pooled (warm spare)", pooled_options());
	measure("unpooled control", solo_options());
	REQUIRE(true);
}

TEST_CASE("The group's capacity fits the host's memslots", "[VmGroup]")
{
	/* KVM_CAP_NR_MEMSLOTS is a wall on B under PerSeat, where the arena costs one
	   memslot per seat, and only a feasibility check under PerGroup, where it
	   costs exactly one however large the group is. Both halves are pinned: this
	   is the assertion the arena slot mode changes most directly. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto& limits = tinykvm::KvmLimits::get();

	SECTION("PerSeat: B leaves room for one memslot per seat") {
		/* One memslot per seat covering its whole partition, plus the group's
		   shared base slots (main memory, the reserved remote slot, and one per
		   master mmap range). KVM_CAP_NR_MEMSLOTS is 32764 on current hosts so it
		   does not bind here, but it is a real wall and MemoryBank::idx is a
		   uint16_t. */
		auto options = pooled_options(tinykvm::VmGroupArenaSlot::PerSeat);
		options.vm_group_size = 0; /* let the group pick B from the host's walls */
		tinykvm::Machine fork { machine, options };
		const auto* group = fork.group();

		const size_t base_slots =
			tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
		REQUIRE(group->capacity() + base_slots <= limits.nr_memslots);
		REQUIRE(group->capacity() + base_slots <= 0xFFFFu);
		/* And the vCPU count wall, which is per struct kvm. */
		REQUIRE(group->capacity() + tinykvm::VmGroup::VCPU_HEADROOM <= limits.max_vcpus);
	}

	SECTION("PerGroup: the arena costs one memslot, whatever B is") {
		/* The memslot cost is now independent of capacity: base_slots + 1, with
		   the arena taking the next free index after the master's mmap ranges. B
		   is bounded by the vCPU count and the arena span only - which is why
		   this test can no longer say anything about nr_memslots beyond "one was
		   left over". */
		auto options = pooled_options(tinykvm::VmGroupArenaSlot::PerGroup);
		options.vm_group_size = 0;
		tinykvm::Machine fork { machine, options };
		const auto* group = fork.group();

		const size_t base_slots =
			tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
		REQUIRE(base_slots + 1 <= limits.nr_memslots);
		REQUIRE(base_slots + 1 <= 0xFFFFu);
		REQUIRE(group->arena_slot() == base_slots);
		REQUIRE(group->capacity() + tinykvm::VmGroup::VCPU_HEADROOM <= limits.max_vcpus);

		/* Independent of capacity, stated as such: a group asked for four seats
		   and a group asked for as many as the host allows use the same one slot,
		   at the same index. */
		auto small = pooled_options(tinykvm::VmGroupArenaSlot::PerGroup);
		small.max_cow_mem = 24ul << 20; /* a group of its own, so B differs too */
		small.vm_group_size = 2;
		tinykvm::Machine other { machine, small };
		REQUIRE(other.group() != group);
		REQUIRE(other.group()->capacity() != group->capacity());
		REQUIRE(other.group()->arena_slot() == base_slots);
	}
}

TEST_CASE("A seat carries no residue from its previous tenant", "[VmGroup]")
{
	/* Plan test 5 / open question 3. A reused vCPU fd carries the previous
	   tenant's xsave area, LAPIC state, MP state and TSC offset, and a reused
	   partition carries its dirty arena pages. Nothing clears those on
	   handback except the full register restore in the fork constructor and
	   the MADV_DONTNEED in release_seat(), so this is the standing proof that
	   those two are in fact sufficient. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto set_value = machine.address_of("set_value");
	const auto read_value = machine.address_of("read_value");
	const auto dirty_fpu = machine.address_of("dirty_fpu");
	REQUIRE(set_value != 0x0);
	REQUIRE(read_value != 0x0);
	REQUIRE(dirty_fpu != 0x0);

	const auto master_fpu = machine.prepared_fpu_registers();
	static constexpr unsigned long PATTERN = 0x4142434445464748UL;

	int   seat_id = -1;
	char* arena_hva = nullptr;
	uint64_t used = 0;
	{
		/* Tenant A dirties the SSE register file and the arena. */
		tinykvm::Machine a { machine, pooled_options() };
		seat_id = a.seat()->kvm_vcpu_id;
		arena_hva = a.seat()->arena_hva;
		REQUIRE(arena_hva != nullptr);

		a.timed_vmcall(set_value, 4.0f, 777);
		REQUIRE(a.return_value() == 777);
		a.timed_vmcall(dirty_fpu, 4.0f, PATTERN);

		/* The dirt is real: without this the test could pass vacuously. */
		const auto a_fpu = a.fpu_registers();
		REQUIRE(memcmp(a_fpu.xmm, master_fpu.xmm, sizeof(a_fpu.xmm)) != 0);
		REQUIRE(memcmp(&a_fpu.xmm[0][0], &PATTERN, sizeof(PATTERN)) == 0);

		used = a.main_memory().banks.partition_used();
		REQUIRE(used > 0);
		/* And the arena really holds A's pages. */
		bool arena_nonzero = false;
		for (uint64_t i = 0; i < used; i += 512) {
			if (arena_hva[i] != 0) { arena_nonzero = true; break; }
		}
		REQUIRE(arena_nonzero);
	}

	/* The seat's arena is handed back scrubbed (MADV_DONTNEED over the used
	   range), before any new tenant has a chance to observe it. */
	for (uint64_t i = 0; i < used; i += 512) {
		REQUIRE(arena_hva[i] == 0);
	}

	/* Tenant B takes the same seat. */
	tinykvm::Machine b { machine, pooled_options() };
	REQUIRE(b.seat()->kvm_vcpu_id == seat_id);
	REQUIRE(b.seat()->arena_hva == arena_hva);

	/* Registers are the master's, not A's. */
	const auto b_fpu = b.fpu_registers();
	REQUIRE(memcmp(b_fpu.xmm, master_fpu.xmm, sizeof(b_fpu.xmm)) == 0);
	REQUIRE(b_fpu.mxcsr == master_fpu.mxcsr);
	REQUIRE(memcmp(b_fpu.fpr, master_fpu.fpr, sizeof(b_fpu.fpr)) == 0);

	/* And so is guest memory: B reads the master's value, not A's marker. */
	b.timed_vmcall(read_value, 4.0f);
	REQUIRE(b.return_value() == 0);

	/* B's own writes still work, on top of master state. */
	b.timed_vmcall(set_value, 4.0f, 5);
	REQUIRE(b.return_value() == 5);
	b.timed_vmcall(read_value, 4.0f);
	REQUIRE(b.return_value() == 5);
}

TEST_CASE("A pooled fork refuses SMP", "[VmGroup]")
{
	/* SMP vCPU ids are dense per-machine (smp.cpp: `1 + m_cpus.size()`), so in
	   a shared struct kvm they collide with sibling seats - and every one of
	   them would consume the group's vCPU capacity permanently, since closing
	   a vCPU fd reclaims nothing. Refused in SMP::prepare_cpus, which every
	   entry point funnels through. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	tinykvm::Machine fork { machine, pooled_options() };
	const auto stack = fork.stack_address();
	REQUIRE_THROWS_AS(
		fork.smp().timed_smpcall(1, stack - 0x20000, 0x4000, get_value, 1.0f),
		tinykvm::MachineException);
	REQUIRE_THROWS_AS(
		fork.smp().timed_smpcall_array(1, stack - 0x20000, 0x4000, get_value, 1.0f, 0x0, 0),
		tinykvm::MachineException);
	REQUIRE(fork.smp_active_count() == 0);

	/* And the fork is unharmed: the refusal is the first thing prepare_cpus
	   does, so no vCPU was created and no group capacity was burnt. */
	REQUIRE(fork.smp_active_count() == 0);
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);
	REQUIRE(fork.group()->high_water() == 1);
	REQUIRE(fork.cpu().kvm_vcpu_id == 0);

	/* NB: no positive control on an unpooled fork. SMP on a *fork* does not
	   work in this tree independently of pooling (it faults setting up the SMP
	   vCPU's kernel structures, which live in the shared master pages) - that
	   is the pre-existing SMP-fork test-coverage debt, not something pooling
	   introduced, and the refusal above is what the plan asks for. The
	   pooling-specific part of the guard is covered by the fact that it reads
	   machine().is_pooled() and nothing else. */
}

#ifndef NDEBUG
TEST_CASE("Pooled page tables stay inside their partition", "[VmGroup]")
{
	/* Plan test 3 / hazard 6. The invariant is load-bearing, not decorative:
	   vMemory::fork_reset()'s copy-back path - fa-serve's production recycle
	   mode - takes the destination of every restored page from the member's
	   own PTEs, so it stays in-partition if and only if they do. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	const auto set_value = machine.address_of("set_value");
	REQUIRE(get_value != 0x0);
	REQUIRE(set_value != 0x0);

	SECTION("It holds for every member, before and after a reset") {
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options()));
			/* A fresh fork still shares the master's page tables. */
			REQUIRE_NOTHROW(forks.back()->assert_pte_partition_invariant());
		}
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			forks[i]->timed_vmcall(set_value, 4.0f, int(100 + i));
			REQUIRE(forks[i]->return_value() == long(100 + i));
			/* Now the member has CoW'ed leaves and page-table pages of its
			   own, all of which must be in its partition. */
			REQUIRE_NOTHROW(forks[i]->assert_pte_partition_invariant());
		}
		/* The copy-back reset (production mode) and the bank-reset path. */
		auto keep = pooled_options();
		keep.reset_keep_all_work_memory = true;
		auto discard = pooled_options();
		discard.reset_keep_all_work_memory = false;
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			forks[i]->reset_to(machine, (i % 2 == 0) ? keep : discard);
			REQUIRE_NOTHROW(forks[i]->assert_pte_partition_invariant());
			forks[i]->timed_vmcall(get_value, 4.0f);
			REQUIRE(forks[i]->return_value() == 1);
			REQUIRE_NOTHROW(forks[i]->assert_pte_partition_invariant());
		}
	}

	SECTION("A PTE poked into a sibling's partition is caught") {
		tinykvm::Machine victim { machine, pooled_options() };
		tinykvm::Machine sibling { machine, pooled_options() };
		REQUIRE(victim.group() == sibling.group());
		REQUIRE(victim.seat()->arena_gpa != sibling.seat()->arena_gpa);

		victim.timed_vmcall(set_value, 4.0f, 11);
		REQUIRE(victim.return_value() == 11);
		sibling.timed_vmcall(set_value, 4.0f, 22);
		REQUIRE(victim.main_memory().banks.partition_used() > 0);
		REQUIRE_NOTHROW(victim.assert_pte_partition_invariant());

		/* Poke a PTE through the victim's *own* page tables. The vmcall above
		   CoW'ed both the leaf it wrote and the page tables above it into the
		   victim's banks, so an entry whose target is already in the victim's
		   partition is by construction one the victim owns - rewriting it
		   disturbs neither the master's shared pagetable nor the sibling.
		   Found by walking rather than by guessing an address: whether a given
		   guest address ends up behind a 4K leaf or a 2MB one is the ELF
		   loader's and the hugepage splitter's business, not this test's. */
		const uint64_t mask = tinykvm::paging_address_mask();
		const uint64_t own_begin = victim.seat()->arena_gpa;
		const uint64_t own_end = own_begin + victim.seat()->arena_size;
		const auto find_own_entry = [&] (size_t want_size, bool want_leaf) {
			uint64_t* found = nullptr;
			tinykvm::foreach_page(victim.main_memory(),
				[&] (uint64_t, uint64_t& entry, size_t size) {
					if (found != nullptr || size != want_size)
						return;
					/* 4K entries are always leaves; above that the PS bit says
					   whether the entry maps memory or points at a table. */
					const bool leaf = (size == PDE64_PTE_SIZE)
						|| ((entry & PDE64_PS) != 0);
					if (leaf != want_leaf)
						return;
					const uint64_t target = entry & mask;
					const uint64_t len = leaf ? uint64_t(size) : 0x1000UL;
					if (target >= own_begin && target + len <= own_end)
						found = &entry;
				}, false);
			return found;
		};

		/* A 4K leaf mapping one of the victim's own CoW'ed pages. */
		uint64_t* entry_ptr = find_own_entry(PDE64_PTE_SIZE, true);
		REQUIRE(entry_ptr != nullptr);
		const uint64_t saved_entry = *entry_ptr;
		/* Point it at the first page of the sibling's partition. */
		*entry_ptr = (saved_entry & ~mask) | sibling.seat()->arena_gpa;

		/* The invariant fires, both on demand and where it guards the hot
		   path: reset_to() must refuse before the copy-back loop can write a
		   restored master page into the sibling's arena.
		   Asserted on the *message*, not just the exception type: MemoryException
		   derives from MachineException, so a plain REQUIRE_THROWS_AS would also
		   be satisfied by a page_at() resolution failure from inside the walk -
		   which is exactly the bug this test is here to catch. */
		using Catch::Matchers::Equals;
		const char* const VIOLATION =
			"A pooled member's page tables leave its arena partition";
		REQUIRE_THROWS_WITH(victim.assert_pte_partition_invariant(), Equals(VIOLATION));
		auto keep = pooled_options();
		keep.reset_keep_all_work_memory = true;
		REQUIRE_THROWS_WITH(victim.reset_to(machine, keep), Equals(VIOLATION));

		/* Restored: the member must leave the pool clean, or the release-path
		   check in ~Machine aborts the process. */
		*entry_ptr = saved_entry;
		REQUIRE_NOTHROW(victim.assert_pte_partition_invariant());

		/* A page-table *page* pointed out of the partition is caught too, not
		   only a leaf mapping: a sibling's arena reinterpreted as page tables is
		   the same isolation break - followed by the hardware page walker as
		   well as by ours - and takes the other branch of the check (one 4K
		   page, rather than the whole span the entry maps).
		   This is the case that requires validating a target *before* descending
		   into it. A walk that resolves the target first (foreach_page does)
		   either throws MemoryException from page_at() or reads the sibling's
		   arena as if it were a page table, and never reaches the check at all -
		   so the message assertion below is load-bearing. */
		uint64_t* table_entry = find_own_entry(PDE64_PT_SIZE, false);
		REQUIRE(table_entry != nullptr); /* a CoW'ed page table of the victim's */
		const uint64_t saved_table = *table_entry;
		*table_entry = (saved_table & ~mask) | sibling.seat()->arena_gpa;
		REQUIRE_THROWS_WITH(victim.assert_pte_partition_invariant(), Equals(VIOLATION));
		*table_entry = saved_table;

		/* And the page-table root (CR3) itself, which nothing the walk visits
		   covers: a root in a sibling's partition would have the hardware page
		   walker start there. */
		auto& vmem = victim.main_memory();
		const uint64_t saved_root = vmem.page_tables;
		vmem.page_tables = sibling.seat()->arena_gpa;
		REQUIRE_THROWS_WITH(victim.assert_pte_partition_invariant(), Equals(VIOLATION));
		vmem.page_tables = saved_root;
		REQUIRE_NOTHROW(victim.assert_pte_partition_invariant());
		REQUIRE_NOTHROW(victim.assert_pte_partition_invariant());

		/* The sibling was never actually touched by any of it. */
		sibling.timed_vmcall(get_value, 4.0f);
		REQUIRE(sibling.return_value() == 23);
	}
}
#endif

/* --- Phase 5: one host mapping per group ---------------------------------- */

TEST_CASE("A group's arena is one host mapping", "[VmGroup]")
{
	/* The residual O(N) that phase 5 removes. Materializing a seat used to cost
	   an mmap plus an mprotect - two VMAs and two mmap_lock write acquisitions -
	   so a group of B seats cost 2B VMAs that every later KVM_CREATE_VM in the
	   process had to walk and lock again. The reservation is now made once, for
	   the whole group, and a seat is an offset into it.

	   Pinned to Off, the mode with nothing per seat at all: Mprotect still pays
	   its 2 VMAs by design (asserted separately below), and Auto would pick
	   between them by kernel version and build mode. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Off);

	/* Warm-up pass, discarded, and deliberately *unpooled*. Constructing a
	   Machine allocates, and a heap growing for the first time can add a VMA of
	   its own, which a process-wide count would charge to a seat. Unpooled forks
	   put the allocator in its steady state without materializing a seat: a
	   pooled warm-up would leave the group as the warm spare, and the measured
	   pass would then recycle its seats instead of creating new ones - which is
	   exactly the work under test. */
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> warmup;
		warmup.reserve(GROUP_SIZE);
		for (size_t i = 0; i < GROUP_SIZE; i++)
			warmup.push_back(std::make_unique<tinykvm::Machine> (machine, solo_options()));
	}

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	forks.reserve(GROUP_SIZE);
	forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	const size_t vmas_one_seat = count_vmas();
	const auto* group = forks[0]->group();
	REQUIRE(group->host_guard() == tinykvm::VmGroupHostGuard::Off);
	REQUIRE(group->high_water() == 1);

	/* I1: the reservation is the group's whole guest-physical span, no more and
	   no less - it is what makes a seat's host address derivable from its index
	   rather than something the seat has to be told. */
	REQUIRE(group->arena_hva() != nullptr);
	REQUIRE(group->arena_span() == uint64_t(group->capacity()) * group->arena_stride());
	/* One VMA for the whole window, and it stays one as seats appear. */
	REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 1);

	/* The memslot equivalent of the VMA count, in the mode this build defaults
	   to: PerGroup makes a seat cost zero memslot operations as well as zero
	   VMAs, PerSeat costs exactly one install per seat. Both are asserted per
	   seat below, so this test states the same claim whichever way
	   TINYKVM_VM_GROUP_ARENA_SLOT_DEFAULT was built. */
	const uint64_t ops_per_seat =
		(group->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerGroup) ? 0u : 1u;
	for (size_t i = 1; i < GROUP_SIZE; i++) {
		const uint64_t ops_before = tinykvm::VmGroup::memslot_ops();
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		REQUIRE(forks.back()->group() == group);
		REQUIRE(group->high_water() == i + 1);
		/* Flat, not merely sublinear: a new seat costs zero VMAs, in the window
		   and in the process. */
		REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 1);
		REQUIRE(count_vmas() == vmas_one_seat);
		REQUIRE(tinykvm::VmGroup::memslot_ops() - ops_before == ops_per_seat);
	}
	REQUIRE(group->live_members() == GROUP_SIZE);
	REQUIRE(group->high_water() == GROUP_SIZE);

	/* And every seat is exactly where its index says it is. The index is the
	   seat's kvm_vcpu_id, not the member's position in this vector: seats come
	   off a LIFO free list, so a member is not guaranteed the seat whose number
	   matches its own construction order. */
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		const auto* seat = forks[i]->seat();
		const uint64_t index = uint64_t(seat->kvm_vcpu_id);
		REQUIRE(index < group->capacity());
		REQUIRE(uintptr_t(seat->arena_hva)
			== uintptr_t(group->arena_hva()) + index * group->arena_stride());
		/* Wholly inside the reservation, guard band included. */
		REQUIRE(uintptr_t(seat->arena_hva) + group->arena_stride()
			<= uintptr_t(group->arena_hva()) + group->arena_span());
	}
}

TEST_CASE("A group's seats are affine to its arena mapping", "[VmGroup]")
{
	/* I2. Every seat of a group has the same guest-physical-to-host delta,
	   because both sides are index * stride from their respective bases. This is
	   what MemoryBanks::allocate_new_bank() relies on when it derives a bank's
	   host address as m_partition_hva + (addr - m_arena_begin): the derivation is
	   affine, so if the constant were per-seat rather than per-group a bank of
	   one member could resolve into the memory of another. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	/* Every mode, because the delta is a property of the reservation and not of
	   how the window is protected. Madvise is included only where the kernel has
	   it; the two others always run. */
	std::vector<tinykvm::VmGroupHostGuard> modes {
		tinykvm::VmGroupHostGuard::Off,
		tinykvm::VmGroupHostGuard::Mprotect,
	};
	if (tinykvm::VmGroup::madv_guard_supported())
		modes.push_back(tinykvm::VmGroupHostGuard::Madvise);

	for (const auto mode : modes) {
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (size_t i = 0; i < GROUP_SIZE; i++)
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, pooled_options(mode)));

		const auto* group = forks[0]->group();
		REQUIRE(group->host_guard() == mode);
		const uint64_t delta = group->arena_base() - uintptr_t(group->arena_hva());
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			const auto* seat = forks[i]->seat();
			REQUIRE(forks[i]->group() == group);
			REQUIRE(seat->arena_gpa - uintptr_t(seat->arena_hva) == delta);
			/* Stated the other way too: the delta reproduces the partition the
			   member's banks were initialised with. */
			REQUIRE(seat->arena_gpa == forks[i]->main_memory().banks.arena_begin());
		}
	}
}

TEST_CASE("Siblings sharing one arena mapping stay isolated", "[VmGroup]")
{
	/* F3's residual weight, now that the partitions are slices of one mapping
	   instead of separate ones. Pinned to Off deliberately: that is the mode with
	   no host-side guard between slices at all, so if anything about the affine
	   derivation, the memslot geometry or the MADV_DONTNEED recycling were wrong,
	   this is the configuration in which it shows up as one member reading or
	   writing another's memory rather than as a SIGSEGV. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto set_value = machine.address_of("set_value");
	const auto read_value = machine.address_of("read_value");
	REQUIRE(set_value != 0x0);
	REQUIRE(read_value != 0x0);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Off);

	/* A pattern per member, written through guest code so it lands in the
	   member's CoW'ed pages, i.e. in its slice of the shared mapping. */
	static constexpr int PATTERN_BASE = 0x51A0;
	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		forks.back()->timed_vmcall(set_value, 4.0f, int(PATTERN_BASE + i));
		REQUIRE(forks.back()->return_value() == long(PATTERN_BASE + i));
	}
	const auto* group = forks[0]->group();
	REQUIRE(group->host_guard() == tinykvm::VmGroupHostGuard::Off);
	REQUIRE(group->live_members() == GROUP_SIZE);

	/* Every member still reads its own pattern: the guest-side statement of
	   isolation. */
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		forks[i]->timed_vmcall(read_value, 4.0f);
		REQUIRE(forks[i]->return_value() == long(PATTERN_BASE + i));
	}

	/* And the host-side statement, which is the one the shared mapping puts at
	   risk: read each slice directly out of the group's reservation and require
	   that a member's pattern appears only in its own. Searched as a raw byte
	   pattern because where inside the partition the guest put `value` is the
	   loader's business, not this test's. */
	const auto find_pattern = [&] (const char* begin, uint64_t len, int pattern) -> bool {
		for (uint64_t off = 0; off + sizeof(int) <= len; off += sizeof(int)) {
			int word = 0;
			memcpy(&word, begin + off, sizeof(word));
			if (word == pattern)
				return true;
		}
		return false;
	};
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		const auto* own = forks[i]->seat();
		const uint64_t used = forks[i]->main_memory().banks.partition_used();
		REQUIRE(used > 0);
		/* The member's own pattern is in its own slice - without this the
		   cross-checks below could pass vacuously. */
		REQUIRE(find_pattern(own->arena_hva, used, PATTERN_BASE + int(i)));
		for (size_t j = 0; j < GROUP_SIZE; j++) {
			if (j == i)
				continue;
			const auto* other = forks[j]->seat();
			REQUIRE(other->arena_hva != own->arena_hva);
			/* No overlap in the first place, which is the structural half. */
			REQUIRE((other->arena_hva + other->arena_size <= own->arena_hva
				|| own->arena_hva + own->arena_size <= other->arena_hva));
			/* And nothing of member i in member j's slice, which is the
			   observed half. */
			REQUIRE(!find_pattern(other->arena_hva,
				forks[j]->main_memory().banks.partition_used(),
				PATTERN_BASE + int(i)));
		}
	}

	/* Recycling: release one member and give its seat to a new tenant. The
	   scrub is a MADV_DONTNEED over a *slice* of a mapping shared with live
	   siblings now, which is the new regression surface - it must zero the slice
	   and touch nothing else. */
	char* const recycled = forks[1]->seat()->arena_hva;
	const uint64_t recycled_used = forks[1]->main_memory().banks.partition_used();
	const int    recycled_id = forks[1]->seat()->kvm_vcpu_id;
	REQUIRE(recycled_used > 0);
	forks[1].reset();

	for (uint64_t off = 0; off < recycled_used; off += 512)
		REQUIRE(recycled[off] == 0);
	/* The siblings are untouched by the scrub, patterns and all. */
	for (size_t j = 0; j < GROUP_SIZE; j++) {
		if (j == 1 || forks[j] == nullptr)
			continue;
		forks[j]->timed_vmcall(read_value, 4.0f);
		REQUIRE(forks[j]->return_value() == long(PATTERN_BASE + int(j)));
		REQUIRE(find_pattern(forks[j]->seat()->arena_hva,
			forks[j]->main_memory().banks.partition_used(),
			PATTERN_BASE + int(j)));
	}

	/* The new tenant lands on the recycled seat and reads the master's state,
	   not its predecessor's. */
	tinykvm::Machine tenant { machine, options };
	REQUIRE(tenant.seat()->kvm_vcpu_id == recycled_id);
	REQUIRE(tenant.seat()->arena_hva == recycled);
	tenant.timed_vmcall(read_value, 4.0f);
	REQUIRE(tenant.return_value() == 0);
	tenant.timed_vmcall(set_value, 4.0f, 0x6E77);
	REQUIRE(tenant.return_value() == 0x6E77);
	/* ...and still nobody else's. */
	for (size_t j = 0; j < GROUP_SIZE; j++) {
		if (j == 1 || forks[j] == nullptr)
			continue;
		REQUIRE(!find_pattern(forks[j]->seat()->arena_hva,
			forks[j]->main_memory().banks.partition_used(), 0x6E77));
	}
}

TEST_CASE("The mprotect guard mode carves a PROT_NONE band per seat", "[VmGroup]")
{
	/* The same claim as "A seat's guard band is unmapped on the host side too",
	   with the mode pinned rather than inherited from Auto, plus the price. The
	   band is now the part of the group's reservation a seat has *not* opened,
	   instead of the tail of a per-seat mapping - the observable layout is
	   identical, which is the point. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Mprotect);

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	forks.reserve(GROUP_SIZE);
	forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	const auto* group = forks[0]->group();
	REQUIRE(group->host_guard() == tinykvm::VmGroupHostGuard::Mprotect);
	REQUIRE(group->high_water() == 1);

	const auto* seat = forks[0]->seat();
	const uint64_t guard = group->arena_stride() - seat->arena_size;
	REQUIRE(guard == tinykvm::VmGroup::GUARD_BAND);
	REQUIRE(maps_perms_at(seat->arena_hva) == "rw-p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size - 1) == "rw-p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size) == "---p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size + guard - 1) == "---p");

	/* Reserved, not merely absent: a PROT_NONE band still occupies the address
	   space, so nothing else can be mapped into it. */
	REQUIRE(!maps_perms_at(seat->arena_hva + seat->arena_size).empty());

	/* The documented price of the mode. Opening a seat's usable part splits the
	   reservation, because PROT_NONE is a VMA attribute and not a PTE one: one RW
	   VMA for the partition and one for the band behind it, per seat. This is the
	   number Madvise and Off exist to avoid, and the reason Auto only picks this
	   mode when a debug build says the backstop is worth it.

	   Counted inside the window, so the claim is about the window and not about
	   whatever else the process is doing; and only over *newly materialized*
	   seats, since a recycled seat was mprotected by its first tenant and costs
	   its second nothing. */
	REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 2);
	for (size_t i = 1; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		REQUIRE(forks.back()->group() == group);
		REQUIRE(group->high_water() == i + 1);
		REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span())
			== 2 * (i + 1));
		const auto* s = forks.back()->seat();
		REQUIRE(maps_perms_at(s->arena_hva) == "rw-p");
		REQUIRE(maps_perms_at(s->arena_hva + s->arena_size) == "---p");
	}
}

TEST_CASE("The madvise guard mode guards without splitting the mapping", "[VmGroup]")
{
	/* MADV_GUARD_INSTALL (Linux 6.13) puts guard markers in the PTEs of a range:
	   a touch faults exactly as PROT_NONE would, but the VMA is untouched, so the
	   band costs no VMA and no mmap_lock write. That is the whole reason the mode
	   exists - it is Mprotect's backstop at Off's price. */
	if (!tinykvm::VmGroup::madv_guard_supported())
		SKIP("kernel has no MADV_GUARD_INSTALL (needs Linux 6.13 or later)");

	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Madvise);
	/* Unpooled warm-up, so the process-wide count below is not charged for the
	   heap's first growth. See the note in "A group's arena is one host mapping". */
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> warmup;
		warmup.reserve(GROUP_SIZE);
		for (size_t i = 0; i < GROUP_SIZE; i++)
			warmup.push_back(std::make_unique<tinykvm::Machine> (machine, solo_options()));
	}

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	forks.reserve(GROUP_SIZE);
	forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	const size_t vmas_one_seat = count_vmas();
	const auto* group = forks[0]->group();
	const auto* seat = forks[0]->seat();
	REQUIRE(group->host_guard() == tinykvm::VmGroupHostGuard::Madvise);
	REQUIRE(group->high_water() == 1);

	/* No split: the band reads with the same permissions as the partition, and
	   neither the window's VMA count nor the process's moves as seats appear. */
	REQUIRE(maps_perms_at(seat->arena_hva) == "rw-p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size) == "rw-p");
	REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 1);
	for (size_t i = 1; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		REQUIRE(forks.back()->group() == group);
		REQUIRE(group->high_water() == i + 1);
		REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 1);
		REQUIRE(count_vmas() == vmas_one_seat);
	}

	/* ...and yet it faults. Probed in a child, because the whole point is that
	   the access is fatal. */
	REQUIRE(probe_write_in_child(seat->arena_hva) == 0);
	REQUIRE(probe_write_in_child(seat->arena_hva + seat->arena_size - 1) == 0);
	REQUIRE(probe_write_in_child(seat->arena_hva + seat->arena_size) == SIGSEGV);
	REQUIRE(probe_write_in_child(
		seat->arena_hva + seat->arena_size
		+ tinykvm::VmGroup::HOST_GUARD_BYTES - 1) == SIGSEGV);

	/* The coverage is bounded, and honestly so: only the first HOST_GUARD_BYTES
	   of the band are guarded. The threat model is a linear overrun, which the
	   first guarded page catches; marking the whole 8 MiB band would cost a page
	   table page per 2 MiB per seat for no added coverage. An access that jumps
	   clean over the guarded prefix therefore does not fault - state it rather
	   than imply the band is covered end to end. */
	REQUIRE(tinykvm::VmGroup::HOST_GUARD_BYTES
		< group->arena_stride() - seat->arena_size);
	REQUIRE(probe_write_in_child(
		seat->arena_hva + seat->arena_size
		+ tinykvm::VmGroup::HOST_GUARD_BYTES) == 0);
}

TEST_CASE("A recycled seat keeps its madvise guard markers", "[VmGroup]")
{
	/* Guard markers are installed once, when the seat is materialized, and the
	   seat outlives every tenant. Recycling runs MADV_DONTNEED over the dirty
	   part of the partition, and the markers have to survive it - both because
	   the range is clamped to arena_size and never reaches them, and because
	   MADV_DONTNEED does not remove guard markers in the first place. If either
	   changed, a reused seat would silently be the unguarded one. */
	if (!tinykvm::VmGroup::madv_guard_supported())
		SKIP("kernel has no MADV_GUARD_INSTALL (needs Linux 6.13 or later)");

	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto set_value = machine.address_of("set_value");
	const auto read_value = machine.address_of("read_value");
	REQUIRE(set_value != 0x0);
	REQUIRE(read_value != 0x0);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Madvise);

	char* arena_hva = nullptr;
	uint64_t arena_size = 0;
	int seat_id = -1;
	{
		/* Dirty the partition, so the release actually has something to scrub. */
		tinykvm::Machine first { machine, options };
		REQUIRE(first.group()->host_guard() == tinykvm::VmGroupHostGuard::Madvise);
		first.timed_vmcall(set_value, 4.0f, 4242);
		REQUIRE(first.return_value() == 4242);
		REQUIRE(first.main_memory().banks.partition_used() > 0);
		arena_hva  = first.seat()->arena_hva;
		arena_size = first.seat()->arena_size;
		seat_id    = first.seat()->kvm_vcpu_id;
		REQUIRE(probe_write_in_child(arena_hva + arena_size) == SIGSEGV);
	}

	/* Same seat, new tenant. */
	tinykvm::Machine second { machine, options };
	REQUIRE(second.seat()->kvm_vcpu_id == seat_id);
	REQUIRE(second.seat()->arena_hva == arena_hva);
	second.timed_vmcall(read_value, 4.0f);
	REQUIRE(second.return_value() == 0);

	/* Still guarded, and the partition still usable right up to the boundary. */
	REQUIRE(probe_write_in_child(arena_hva + arena_size - 1) == 0);
	REQUIRE(probe_write_in_child(arena_hva + arena_size) == SIGSEGV);
}

TEST_CASE("The off guard mode leaves the whole stride accessible", "[VmGroup]")
{
	/* Off is the flat-VMA goal state: the reservation is mapped RW once and
	   nothing is done per seat, so there is no host-side backstop between
	   adjacent slices. That is a deliberate trade, and this test states both
	   halves of it - what is given up, and what is not. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Off);
	/* Unpooled warm-up, so the process-wide count below is not charged for the
	   heap's first growth. See the note in "A group's arena is one host mapping". */
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> warmup;
		warmup.reserve(GROUP_SIZE);
		for (size_t i = 0; i < GROUP_SIZE; i++)
			warmup.push_back(std::make_unique<tinykvm::Machine> (machine, solo_options()));
	}

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	forks.reserve(GROUP_SIZE);
	forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	const size_t vmas_one_seat = count_vmas();
	const auto* group = forks[0]->group();
	const auto* seat = forks[0]->seat();
	REQUIRE(group->host_guard() == tinykvm::VmGroupHostGuard::Off);
	REQUIRE(group->high_water() == 1);

	/* Given up: the whole stride reads as one accessible region, band included,
	   and a write into the band does not fault. */
	REQUIRE(maps_perms_at(seat->arena_hva) == "rw-p");
	REQUIRE(maps_perms_at(seat->arena_hva + seat->arena_size) == "rw-p");
	REQUIRE(maps_perms_at(seat->arena_hva + group->arena_stride() - 1) == "rw-p");
	REQUIRE(probe_write_in_child(seat->arena_hva + seat->arena_size) == 0);

	/* Bought: nothing per seat, in the window or in the process. */
	REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 1);
	for (size_t i = 1; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		REQUIRE(forks.back()->group() == group);
		REQUIRE(group->high_water() == i + 1);
		REQUIRE(count_vmas_in(group->arena_hva(), group->arena_span()) == 1);
		REQUIRE(count_vmas() == vmas_one_seat);
	}

	/* Not given up: the wall that keeps a member's banks inside its partition,
	   which is in the allocator, where a bank's host address is derived - and is
	   unconditional in both the guard mode and the arena slot mode. This is the
	   primary documented wall now, because the other one moved: what a *guest*
	   touching a band GPA gets depends on the arena slot mode.

	     PerSeat, any guard mode: the seat's memslot stops at arena_size, so the
	       band has no backing in the group's VM at all - an MMIO exit, thrown
	       unconditionally and for free.
	     PerGroup + Mprotect: the band is inside the group's one memslot, so KVM
	       resolves it through the host page behind it, which is PROT_NONE for the
	       band's whole length - get_user_pages() fails, KVM_RUN returns -EFAULT,
	       the write never lands and the member dies. No timer is involved.
	     PerGroup + Madvise: the same, for the first HOST_GUARD_BYTES of the band;
	       beyond that the touch succeeds.
	     PerGroup + Off: the touch succeeds silently, anywhere in the band.

	   All four are exercised in "A guest touch of a guard band"; this test states
	   only the host side, which is why it does not pin the slot mode.

	   Reaching the allocator wall takes deliberate effort, and that is by design: the
	   partition is arena_size = max_cow_mem rounded up to a whole bank, so the
	   working-memory ceiling always runs out first and the wall is a backstop
	   rather than the operative limit. Raising the ceiling past the partition
	   with set_max_pages() is what exposes it - allocate_new_bank() refuses
	   before it derives a host address, which is precisely what stops an
	   overrun from resolving into the next slice. */
	auto& banks = forks[0]->main_memory().banks;
	REQUIRE(banks.is_partitioned());
	REQUIRE(banks.partition_used() <= seat->arena_size);
	const size_t page_size = tinykvm::vMemory::PageSize();
	banks.set_max_pages((seat->arena_size + 4 * tinykvm::VmGroup::BANK_ALIGNMENT)
		/ page_size, 0);
	bool refused = false;
	for (size_t i = 0; i < 16 && !refused; i++) {
		try {
			banks.get_available_bank(tinykvm::MemoryBank::N_PAGES);
		} catch (const tinykvm::MemoryException& e) {
			using Catch::Matchers::Equals;
			REQUIRE_THAT(e.what(),
				Equals("Memory bank exceeds the VM group arena partition"));
			refused = true;
		}
	}
	REQUIRE(refused);
	/* Nothing was handed out past the partition on the way there. */
	REQUIRE(banks.partition_used() <= seat->arena_size);

	/* That member's banks are now in a state its destructor should not be asked
	   to reason about, so retire it explicitly before the group is judged. */
	forks[0].reset();
}

TEST_CASE("Retiring a group returns its arena mapping to the host", "[VmGroup]")
{
	/* Proof of I5 and of the destructor's ordering: one munmap releases the
	   whole group window, and it releases all of it. A leak here would be
	   invisible to every other test - the address space is enormous and nothing
	   would fail - but would accumulate one reservation per retired group for
	   the life of the process. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Off);
	const size_t vms_baseline = count_kvm_vms();

	/* One group, filled and drained. It is kept as the warm spare, so this is
	   the "one group resident" reference point - and the allocator is warm by
	   the end of it. */
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		forks.reserve(GROUP_SIZE);
		for (size_t i = 0; i < GROUP_SIZE; i++)
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	}
	REQUIRE(machine.groups().group_count() == 1);
	REQUIRE(count_kvm_vms() == vms_baseline + 1);
	const size_t vmas_one_group = count_vmas();

	/* Now B+1 members: a second group opens. Both were reserved with the same
	   stride and capacity, so the two windows are the same size. */
	char* retiring_hva = nullptr;
	uint64_t retiring_span = 0;
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		forks.reserve(GROUP_SIZE + 1);
		for (size_t i = 0; i < GROUP_SIZE + 1; i++)
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		REQUIRE(machine.groups().group_count() == 2);
		REQUIRE(count_kvm_vms() == vms_baseline + 2);
		const auto* first_group = forks[0]->group();
		REQUIRE(forks[GROUP_SIZE]->group() != first_group);
		retiring_hva  = first_group->arena_hva();
		retiring_span = first_group->arena_span();
		REQUIRE(retiring_hva != nullptr);
		REQUIRE(maps_perms_at(retiring_hva) == "rw-p");
		REQUIRE(maps_perms_at(retiring_hva + retiring_span - 1) == "rw-p");
	}
	/* The members are destroyed in order, so group 1 empties first and keeps the
	   spare; group 2 then empties, and with two empty eligible groups and one
	   spare, group 1 is retired. */
	REQUIRE(machine.groups().group_count() == 1);
	REQUIRE(count_kvm_vms() == vms_baseline + 1);

	/* Gone, from the first byte to the last: one munmap of the whole span, not
	   of a stride or of whatever the last seat happened to own. */
	REQUIRE(maps_perms_at(retiring_hva) == "");
	REQUIRE(maps_perms_at(retiring_hva + retiring_span - 1) == "");
	REQUIRE(maps_perms_at(retiring_hva + retiring_span / 2) == "");

	/* And the process is back to one group's worth of VMAs. */
	REQUIRE(count_vmas() == vmas_one_group);
}

TEST_CASE("The host guard mode is part of group eligibility", "[VmGroup]")
{
	/* The mode decides how the group's window is *mapped*, so it cannot be
	   retrofitted onto a group that already exists - which puts it in the same
	   class as the frozen working-memory ceiling: a member that explicitly asked
	   for a mode must get a group that resolved to it, and a mismatch has to mean
	   "open a new group" rather than "this fork cannot be built". */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	/* Group A, explicitly Off. */
	tinykvm::Machine off_member { machine, pooled_options(tinykvm::VmGroupHostGuard::Off) };
	off_member.timed_vmcall(get_value, 4.0f);
	REQUIRE(off_member.return_value() == 1);
	const auto* group_a = off_member.group();
	REQUIRE(group_a->host_guard() == tinykvm::VmGroupHostGuard::Off);
	REQUIRE(machine.groups().group_count() == 1);
	REQUIRE(group_a->live_members() == 1);
	REQUIRE(group_a->capacity() > 1); /* A has room, so only mode can refuse it */

	/* A member wanting Mprotect cannot have A's window, which is mapped RW
	   throughout rather than reserved PROT_NONE - so a second group opens, even
	   though A is nowhere near full. */
	tinykvm::Machine mp_member { machine, pooled_options(tinykvm::VmGroupHostGuard::Mprotect) };
	mp_member.timed_vmcall(get_value, 4.0f);
	REQUIRE(mp_member.return_value() == 1);
	const auto* group_b = mp_member.group();
	REQUIRE(group_b != group_a);
	REQUIRE(group_b->host_guard() == tinykvm::VmGroupHostGuard::Mprotect);
	REQUIRE(machine.groups().group_count() == 2);
	/* A is untouched and still holds its member. */
	REQUIRE(group_a->live_members() == 1);

	/* A second explicit member of each mode reuses its own group rather than
	   opening a third: the test is "resolved mode equals requested mode", not
	   "every explicit request is its own group". */
	tinykvm::Machine off_two { machine, pooled_options(tinykvm::VmGroupHostGuard::Off) };
	REQUIRE(off_two.group() == group_a);
	tinykvm::Machine mp_two { machine, pooled_options(tinykvm::VmGroupHostGuard::Mprotect) };
	REQUIRE(mp_two.group() == group_b);
	REQUIRE(machine.groups().group_count() == 2);

	/* And Auto joins whatever is there. It means "whatever this host can give",
	   which a group that already exists has already decided, so it must not open
	   a third group - the case that matters, because Auto is the default and a
	   bifurcating default would double the number of struct kvms. */
	auto auto_options = pooled_options();
	auto_options.lazy_vcpu_mmap = true;
	REQUIRE(auto_options.vm_group_host_guard == tinykvm::VmGroupHostGuard::Auto);
	tinykvm::Machine auto_member { machine, auto_options };
	REQUIRE(machine.groups().group_count() == 2);
	REQUIRE((auto_member.group() == group_a || auto_member.group() == group_b));
	auto_member.timed_vmcall(get_value, 4.0f);
	REQUIRE(auto_member.return_value() == 1);
}

/* --- Phase 6: one memslot per group --------------------------------------- */

/* A guest-virtual mapping of the 2 MiB of guest-physical memory at @gpa, poked
   into @m's own page tables, and what has to be undone afterwards. Poking a
   page-table entry is the only way to make a guest touch a guest-physical address
   the loader never mapped - a guard band, in particular.

   Three properties are load-bearing.

   The entry lives in one of *this member's own* page directories. It is found by
   walking for a PD entry that points at a page table inside the member's
   partition: the vmcall that dirtied a page CoW'ed both that page table and the
   directory above it, so such an entry is by construction one the member owns,
   and writing a neighbouring slot of that directory disturbs neither the
   master's shared tables nor a sibling. Found by walking rather than by guessing
   an address, because which guest addresses sit behind which level of table is
   the ELF loader's and the hugepage splitter's business.

   The entry that is rewritten is one the guest has never accessed: a 2 MiB leaf
   of the identity map whose target is *outside* main memory. setup_amd64_paging()
   identity-maps a whole gigapage of 2 MiB leaves regardless of max_mem, so a VM
   with 8 MiB of memory has hundreds of present leaves pointing at guest-physical
   addresses nothing backs - and an address nothing backs is one the guest cannot
   have touched, because touching it would have exited to MMIO. That matters
   because x86 caches translations: re-pointing an entry the guest *has* used
   would be served out of its TLB and the access would never reach the address
   under test, which looks exactly like "the guard did not fire". (There is no
   free slot to use instead: the identity map fills its page directory, and the
   page tables the hugepage splitter produces are fully populated too.)

   And it is a 2 MiB leaf rather than a 4K one, which also gives the caller a
   whole 2 MiB window into the band, so one mapping serves touches at several
   offsets. */
struct PokedMapping {
	uint64_t* entry = nullptr;  /* the entry that was rewritten */
	uint64_t  saved = 0;        /* what it held before */
	uint64_t  vaddr = 0;        /* the guest virtual address it now maps */
};
static PokedMapping map_2mb_into(tinykvm::Machine& m, uint64_t gpa)
{
	REQUIRE(gpa % PDE64_PT_SIZE == 0);
	const uint64_t mask = tinykvm::paging_address_mask();
	const auto& mem = m.main_memory();
	const uint64_t main_end = mem.physbase + mem.size;
	const uint64_t own_begin = m.seat()->arena_gpa;
	const uint64_t own_end = own_begin + m.seat()->arena_size;
	const size_t page = tinykvm::vMemory::PageSize();

	/* Every page directory this member owns a copy of: one holding an entry that
	   points at a page table inside the member's own partition. */
	std::vector<std::pair<uint64_t*, uint64_t>> owned;
	tinykvm::foreach_page(m.main_memory(),
		[&] (uint64_t vaddr, uint64_t& entry, size_t size) {
			/* A 2 MiB-spanning entry without PS: a pointer to a page table. */
			if (size != PDE64_PT_SIZE || (entry & PDE64_PS) != 0)
				return;
			const uint64_t target = entry & mask;
			if (target >= own_begin && target + page <= own_end)
				owned.push_back({&entry, vaddr});
		}, false);
	REQUIRE(!owned.empty());

	PokedMapping poked;
	for (const auto& [known, known_vaddr] : owned) {
		uint64_t* const dir =
			(uint64_t *) (uintptr_t(known) & ~(uintptr_t(page) - 1));
		const size_t known_index = size_t(known - dir);
		for (size_t i = 0; i < page / sizeof(uint64_t); i++) {
			const uint64_t entry = dir[i];
			if ((entry & (PDE64_PRESENT | PDE64_PS)) != (PDE64_PRESENT | PDE64_PS))
				continue;
			const uint64_t vaddr = known_vaddr
				+ (int64_t(i) - int64_t(known_index)) * int64_t(PDE64_PT_SIZE);
			/* A pristine identity leaf past the end of main memory: still
			   target == vaddr, so nothing has remapped it to a bank (the guest's
			   heap and its banks live in this same identity range, and those
			   pages the guest very much has touched), and nothing backs it, so
			   the guest cannot have touched it either - a touch would have exited
			   to MMIO. Hence no TLB entry, and the poke below takes effect. */
			const uint64_t target = entry & mask;
			if (target != vaddr || target < main_end)
				continue;
			poked.entry = &dir[i];
			poked.saved = entry;
			poked.vaddr = vaddr;
			/* Present, writable and user-accessible, exactly as the member's own
			   data pages are - the touch is performed by guest code in usermode. */
			*poked.entry = gpa | PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
			break;
		}
		if (poked.entry != nullptr)
			break;
	}
	REQUIRE(poked.entry != nullptr);
	return poked;
}

TEST_CASE("A group installs its arena memslot once, and then never", "[VmGroup]")
{
	/* The phase-6 claim, as a count rather than a comment. Under PerGroup the
	   arena is one memslot installed at construction, so materializing a seat,
	   running it, resetting it, releasing it and handing the seat to a new tenant
	   all cost zero KVM_SET_USER_MEMORY_REGION - which matters because that ioctl
	   takes slots_lock and ends in synchronize_srcu_expedited() on a VM whose
	   other members are inside KVM_RUN.
	   The PerSeat control is what makes the count meaningful: the same sequence
	   there costs exactly one install per seat ever materialized, and none for a
	   recycled one. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	const auto set_value = machine.address_of("set_value");
	REQUIRE(get_value != 0x0);
	REQUIRE(set_value != 0x0);

	SECTION("PerGroup: base slots plus one, and then nothing") {
		const auto options = pooled_options(tinykvm::VmGroupArenaSlot::PerGroup);

		const uint64_t before = tinykvm::VmGroup::memslot_ops();
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		const auto* group = forks[0]->group();
		REQUIRE(group->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerGroup);

		/* Everything the group installs, once: main memory at slot 0, one slot per
		   master mmap range, and the arena. That is base_slots operations - the
		   arena takes the arithmetic place of the reserved remote slot, which
		   BASE_MEMSLOTS counts but nobody ever installs. */
		const size_t base_slots =
			tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
		const uint64_t at_construction = tinykvm::VmGroup::memslot_ops() - before;
		REQUIRE(at_construction == base_slots);
		REQUIRE(group->arena_slot() == base_slots);

		/* Zero from here on. Every operation a member can perform, in the order a
		   serving host performs them. */
		const uint64_t after_ctor = tinykvm::VmGroup::memslot_ops();
		forks[0]->timed_vmcall(set_value, 4.0f, 1234);
		REQUIRE(forks[0]->return_value() == 1234);
		for (size_t i = 1; i < GROUP_SIZE; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
			REQUIRE(forks.back()->group() == group);
			forks.back()->timed_vmcall(get_value, 4.0f);
			REQUIRE(forks.back()->return_value() == 1);
		}
		REQUIRE(group->high_water() == GROUP_SIZE);
		/* Both reset paths: the copy-back one production uses, and the bank-reset
		   one. Neither may install or delete anything. */
		auto keep = options;
		keep.reset_keep_all_work_memory = true;
		auto discard = options;
		discard.reset_keep_all_work_memory = false;
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			forks[i]->reset_to(machine, (i % 2 == 0) ? keep : discard);
			forks[i]->timed_vmcall(get_value, 4.0f);
			REQUIRE(forks[i]->return_value() == 1);
		}
		/* And every seat is served by the group's one slot, which is what makes
		   the count above a statement about the geometry and not just about a
		   call site. */
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			REQUIRE(forks[i]->seat()->memslot == group->arena_slot());
		}
		/* Release everything, then refill the same group from its free list. */
		forks.clear();
		REQUIRE(machine.groups().group_count() == 1);
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
			REQUIRE(forks.back()->group() == group);
			forks.back()->timed_vmcall(get_value, 4.0f);
		}
		REQUIRE(group->high_water() == GROUP_SIZE);
		REQUIRE(tinykvm::VmGroup::memslot_ops() == after_ctor);
	}

	SECTION("PerSeat control: one install per seat materialized") {
		const auto options = pooled_options(tinykvm::VmGroupArenaSlot::PerSeat);

		const uint64_t before = tinykvm::VmGroup::memslot_ops();
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		const auto* group = forks[0]->group();
		REQUIRE(group->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerSeat);
		REQUIRE(group->arena_slot() == 0); /* unused in this mode */

		const size_t base_slots =
			tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
		/* One less than PerGroup's construction cost - the arena's slot is not
		   installed here - plus one for the seat that was just materialized. */
		REQUIRE(tinykvm::VmGroup::memslot_ops() - before == base_slots);
		REQUIRE(forks[0]->seat()->memslot == base_slots);

		for (size_t i = 1; i < GROUP_SIZE; i++) {
			const uint64_t ops_before = tinykvm::VmGroup::memslot_ops();
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
			REQUIRE(forks.back()->group() == group);
			REQUIRE(tinykvm::VmGroup::memslot_ops() - ops_before == 1);
			/* A slot of its own, and a distinct one. */
			REQUIRE(forks.back()->seat()->memslot != forks[0]->seat()->memslot);
		}
		/* Recycling a seat costs nothing even here: the slot belongs to the seat,
		   not to the tenant. */
		forks.clear();
		const uint64_t after_drain = tinykvm::VmGroup::memslot_ops();
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
			REQUIRE(forks.back()->group() == group);
		}
		REQUIRE(group->high_water() == GROUP_SIZE);
		REQUIRE(tinykvm::VmGroup::memslot_ops() == after_drain);
	}
}

TEST_CASE("A guest touch of a guard band", "[VmGroup]")
{
	/* The trade phase 6 makes, stated in full. Under PerSeat a seat's memslot
	   stops at arena_size, so a band GPA has no backing in the group's VM and a
	   guest touching it takes an MMIO exit that Machine throws on -
	   unconditionally, and for free. Under PerGroup the band is inside the
	   group's one memslot, so KVM resolves the access through the host page
	   behind it and the band's guard becomes whatever the host guard mode put
	   there: PROT_NONE (Mprotect) and MADV_GUARD_INSTALL markers (Madvise) both
	   fail the get_user_pages() in KVM's fault path, while Off has nothing there
	   at all and the write silently faults in an anonymous page.

	   What a refused touch is *called* is partly the kernel's business, so the
	   guarded arms assert on the exception type plus two properties of the message
	   rather than on one exact string: KVM_RUN comes back -EFAULT (immediately, on
	   6.8 - there is no fault-retry loop and no timeout involved), and depending on
	   whether the kernel fills in KVM_EXIT_MEMORY_FAULT that surfaces as a
	   MemoryException or as a plain MachineException, with a different message
	   each way. What the arms do require, beyond "something threw":
	
	     Not a MachineTimeoutException. An EFAULT relabelled as a timeout is what
	       vcpu_run.cpp did before phase 6 (it tested timer_ticks, which holds the
	       *configured* timeout, so every failure inside a timed run became one), and
	       it is worth an explicit assertion because it hid the errno of exactly this
	       class of fault - and because a guard that has silently stopped working
	       would then look identical to a slow one.
	     Not "outside physical memory". That is the MMIO-exit message, i.e. what a
	       band touch produces when it never reaches a memslot at all - which is also
	       what a *failed PTE poke* produces, since the address the guest then
	       touches is whatever the untouched identity leaf pointed at. Asserting only
	       the base type would let a broken setup pass this test while proving
	       nothing about the guard.
	
	   The band-touch arms use the same 4-second timeout as every other arm in this
	   file. Nothing here is expected to reach a timer, so a short one would only
	   convert a guard failure on a loaded box into a passing timeout. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto set_value = machine.address_of("set_value");
	const auto touch_at = machine.address_of("touch_at");
	const auto spin_forever = machine.address_of("spin_forever");
	REQUIRE(set_value != 0x0);
	REQUIRE(touch_at != 0x0);
	REQUIRE(spin_forever != 0x0);
	static constexpr int BAND_PATTERN = 0x0BADBA5E;

	/* The guarded arms' verdict, in one place. @call must throw, must not throw a
	   timeout, and must not throw the MMIO message - see the two properties above.
	   The positive half is asserted too where the kernel makes it deterministic:
	   every message vcpu_run.cpp derives from an EFAULT names the fault
	   ("...EFAULT..." or "...KVM_EXIT_MEMORY_FAULT..."), so requiring "FAULT" holds
	   for either shape while still failing on anything that is not one of them. */
	const auto require_band_fault = [] (const char* what_arm, auto&& call) {
		bool threw = false;
		try {
			call();
		} catch (const tinykvm::MachineTimeoutException& e) {
			threw = true;
			FAIL(std::string(what_arm) + ": a guarded band touch was reported as an"
				" execution timeout, not as the fault it is: " + e.what());
		} catch (const tinykvm::MachineException& e) {
			threw = true;
			const std::string message = e.what();
			INFO(std::string(what_arm) + " threw: " + message);
			REQUIRE(message.find("outside physical memory") == std::string::npos);
			REQUIRE(message.find("FAULT") != std::string::npos);
		}
		REQUIRE(threw);
	};

	/* Dirty the member, so it has page tables of its own, then map 2 MiB of its
	   own guard band - starting @band_offset bytes into it - at a guest virtual
	   address that was not mapped before. The band starts at a 2 MiB boundary
	   (I6), so any 2 MiB-aligned offset into it can be mapped this way. Undone by
	   zeroing the entry again. */
	const auto map_band = [&] (tinykvm::Machine& m, uint64_t band_offset) {
		m.timed_vmcall(set_value, 4.0f, 7);
		REQUIRE(m.return_value() == 7);
		return map_2mb_into(m,
			m.seat()->arena_gpa + m.seat()->arena_size + band_offset);
	};

	SECTION("PerSeat: the band is outside every memslot, and the touch throws") {
		tinykvm::Machine fork { machine,
			pooled_options(tinykvm::VmGroupHostGuard::Off,
				tinykvm::VmGroupArenaSlot::PerSeat) };
		const auto* seat = fork.seat();
		const PokedMapping band = map_band(fork, 0);

		/* Off mode, so the host side of the band is plain RW memory: if the write
		   were reaching the host at all, it would be visible here. It is not -
		   the guest never gets that far, because the band has no memslot. */
		int host_word = 0;
		memcpy(&host_word, seat->arena_hva + seat->arena_size, sizeof(host_word));
		REQUIRE(host_word == 0);

		/* The MMIO message, positively: this is the signature the guarded arms
		   below assert the *absence* of, so state here what it looks like when it is
		   the correct answer. It is tinykvm's own string from the KVM_EXIT_MMIO
		   handler, not the kernel's, so it is the same on every host - and it is what
		   a band touch that never reached a memslot looks like. */
		bool threw = false;
		try {
			fork.timed_vmcall(touch_at, 4.0f, band.vaddr, BAND_PATTERN);
		} catch (const tinykvm::MachineException& e) {
			threw = true;
			const std::string message = e.what();
			INFO(std::string("PerSeat threw: ") + message);
			REQUIRE(message.find("outside physical memory") != std::string::npos);
		}
		REQUIRE(threw);
		memcpy(&host_word, seat->arena_hva + seat->arena_size, sizeof(host_word));
		REQUIRE(host_word == 0);

		*band.entry = band.saved;
	}

	SECTION("PerGroup + Mprotect: the band is PROT_NONE, and the touch throws") {
		tinykvm::Machine fork { machine,
			pooled_options(tinykvm::VmGroupHostGuard::Mprotect,
				tinykvm::VmGroupArenaSlot::PerGroup) };
		REQUIRE(fork.group()->host_guard() == tinykvm::VmGroupHostGuard::Mprotect);
		/* The last page of the band, not its first: the mode's coverage is a VMA
		   attribute, so unlike Madvise's it does not run out. */
		const uint64_t band_len =
			fork.group()->arena_stride() - fork.seat()->arena_size;
		REQUIRE(band_len % PDE64_PT_SIZE == 0);
		const PokedMapping band = map_band(fork, band_len - PDE64_PT_SIZE);
		const uint64_t last_page =
			band.vaddr + PDE64_PT_SIZE - tinykvm::vMemory::PageSize();
		/* KVM cannot get a writable page for the band's PROT_NONE host memory, so
		   get_user_pages() fails in the fault path and KVM_RUN returns -EFAULT on the
		   spot. The full four seconds, and an explicit "not a timeout": the write
		   never lands, and it never lands *as a fault*. */
		require_band_fault("PerGroup + Mprotect", [&] {
			fork.timed_vmcall(touch_at, 4.0f, last_page, BAND_PATTERN);
		});
		/* No host-side read of the band here, unlike the Off arms: in this mode the
		   band is PROT_NONE in *this* process too, which is the whole point, so the
		   test would take the SIGSEGV it is asserting the guest cannot avoid. */
		*band.entry = band.saved;
	}

	SECTION("PerGroup + Off: the touch succeeds, and the host can see it") {
		/* The trade, demonstrated rather than described. This is the shipped
		   default below kernel 6.13, and it is why the phase needed a mode. */
		tinykvm::Machine fork { machine,
			pooled_options(tinykvm::VmGroupHostGuard::Off,
				tinykvm::VmGroupArenaSlot::PerGroup) };
		REQUIRE(fork.group()->host_guard() == tinykvm::VmGroupHostGuard::Off);
		REQUIRE(fork.group()->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerGroup);
		const auto* seat = fork.seat();

		int host_word = 0;
		memcpy(&host_word, seat->arena_hva + seat->arena_size, sizeof(host_word));
		REQUIRE(host_word == 0);

		const PokedMapping band = map_band(fork, 0);
		REQUIRE_NOTHROW(fork.timed_vmcall(touch_at, 4.0f, band.vaddr, BAND_PATTERN));
		REQUIRE(fork.return_value() == BAND_PATTERN);

		/* Where it went: the group's one memslot maps the band affinely, so the
		   guest's write landed at the band's host address. Nothing faulted, and
		   nothing complained. */
		memcpy(&host_word, seat->arena_hva + seat->arena_size, sizeof(host_word));
		REQUIRE(host_word == BAND_PATTERN);

#ifndef NDEBUG
		/* And the wall that is left. The band is inside the group's arena and
		   outside this member's partition, so the PTE-partition invariant - which
		   runs before every copy-back reset in any build without NDEBUG, i.e. in
		   every build the cc crate makes - refuses the state that made the touch
		   possible, both on demand and where it guards the hot path. */
		using Catch::Matchers::Equals;
		const char* const VIOLATION =
			"A pooled member's page tables leave its arena partition";
		REQUIRE_THROWS_WITH(fork.assert_pte_partition_invariant(), Equals(VIOLATION));
		auto keep = pooled_options(tinykvm::VmGroupHostGuard::Off,
			tinykvm::VmGroupArenaSlot::PerGroup);
		keep.reset_keep_all_work_memory = true;
		REQUIRE_THROWS_WITH(fork.reset_to(machine, keep), Equals(VIOLATION));
#endif
		/* Restored, so the member leaves the pool clean. */
		*band.entry = band.saved;
		REQUIRE_NOTHROW(fork.assert_pte_partition_invariant());
	}

	SECTION("PerGroup + Madvise: guarded for HOST_GUARD_BYTES, then not") {
		if (!tinykvm::VmGroup::madv_guard_supported())
			SKIP("kernel has no MADV_GUARD_INSTALL (needs Linux 6.13 or later)");

		const auto options = pooled_options(tinykvm::VmGroupHostGuard::Madvise,
			tinykvm::VmGroupArenaSlot::PerGroup);
		/* One member per touch: a KVM_RUN that failed leaves a vCPU whose state
		   this test has no business reasoning about, so the two halves do not
		   share a fork. */
		{
			tinykvm::Machine guarded { machine, options };
			REQUIRE(guarded.group()->host_guard() == tinykvm::VmGroupHostGuard::Madvise);
			const PokedMapping band = map_band(guarded, 0);
			/* A guard marker fails the same get_user_pages() a PROT_NONE page
			   does, so this is the Mprotect arm's verdict verbatim - including
			   "not a timeout". */
			require_band_fault("PerGroup + Madvise", [&] {
				guarded.timed_vmcall(touch_at, 4.0f, band.vaddr, BAND_PATTERN);
			});
			*band.entry = band.saved;
		}
		{
			/* Beyond the guarded prefix the band is ordinary RW memory again, and
			   the touch is as silent as it is in Off. Stated rather than implied:
			   the mode covers the linear-overrun class, not the whole band. */
			tinykvm::Machine beyond { machine, options };
			const auto* seat = beyond.seat();
			const uint64_t guarded_len = tinykvm::VmGroup::HOST_GUARD_BYTES;
			REQUIRE(guarded_len < beyond.group()->arena_stride() - seat->arena_size);
			REQUIRE(guarded_len < PDE64_PT_SIZE); /* inside the mapped 2 MiB window */
			const PokedMapping band = map_band(beyond, 0);
			REQUIRE_NOTHROW(beyond.timed_vmcall(touch_at, 4.0f,
				band.vaddr + guarded_len, BAND_PATTERN));
			REQUIRE(beyond.return_value() == BAND_PATTERN);
			int host_word = 0;
			memcpy(&host_word,
				seat->arena_hva + seat->arena_size + guarded_len, sizeof(host_word));
			REQUIRE(host_word == BAND_PATTERN);
			*band.entry = band.saved;
		}
	}

	SECTION("A genuine timeout is still a timeout") {
		/* The control for the two arms above, and the other half of what the
		   classification in vcpu_run.cpp has to get right: a KVM_RUN failure is a
		   MachineTimeoutException when the execution timer fired, and only then.
		   Requiring "not a timeout" of a band touch is worth nothing unless a real
		   timeout still is one - fa-serve's request deadline is that exception, so a
		   fix that made faults honest by making timeouts unrecognizable would be a
		   worse bug than the one it replaced. Same group configuration as the
		   Mprotect arm, so the timer is the only difference between them. */
		tinykvm::Machine fork { machine,
			pooled_options(tinykvm::VmGroupHostGuard::Mprotect,
				tinykvm::VmGroupArenaSlot::PerGroup) };
		bool timed_out = false;
		try {
			fork.timed_vmcall(spin_forever, 0.25f);
		} catch (const tinykvm::MachineTimeoutException& e) {
			timed_out = true;
			INFO(std::string("timeout arm threw: ") + e.what());
			/* And it carries the configured timeout, which is what the caller
			   reports: 0.25 s, not whatever errno the ioctl came back with. */
			REQUIRE(e.seconds() == 0.25f);
		}
		REQUIRE(timed_out);
	}
}

TEST_CASE("Siblings stay isolated across a guardless band", "[VmGroup]")
{
	/* The isolation claim in the weakest configuration phase 6 ships: PerGroup +
	   Off, where the guard bands are inside the group's one memslot and nothing
	   protects them on either side. If anything about the affine derivation, the
	   single slot's geometry or the MADV_DONTNEED recycling were wrong, this is
	   the configuration in which it shows up as one member reading or writing
	   another's memory rather than as a fault.

	   Bands are written from the *host* here, which is the honest way to model
	   the class this trade exposes: tinykvm's own C++ walking off the end of a
	   partition. What the test then requires is that band dirt stays in the band
	   - no member's partition is disturbed by it, no member's guest state changes
	   because of it - and that it is never scrubbed, because release_seat() clamps
	   its madvise to arena_size. Band dirt lives for the lifetime of the group. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto set_value = machine.address_of("set_value");
	const auto read_value = machine.address_of("read_value");
	REQUIRE(set_value != 0x0);
	REQUIRE(read_value != 0x0);

	const auto options = pooled_options(tinykvm::VmGroupHostGuard::Off,
		tinykvm::VmGroupArenaSlot::PerGroup);

	/* High-entropy 32-bit bases, in the shape of BAND_PATTERN above, because both
	   are searched for *negatively* over every used byte of every partition below:
	   a short pattern like 0x7A00 occurs in ordinary guest data by coincidence often
	   enough to fail this test for no reason. The low nibble is left free so
	   PATTERN_BASE + i stays distinct for GROUP_SIZE members without colliding with
	   the band series. */
	static constexpr int PATTERN_BASE = 0x7A5EED10;
	static constexpr int BAND_BASE    = 0x0BA0DF10;
	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
		forks.back()->timed_vmcall(set_value, 4.0f, int(PATTERN_BASE + i));
		REQUIRE(forks.back()->return_value() == long(PATTERN_BASE + i));
	}
	const auto* group = forks[0]->group();
	REQUIRE(group->host_guard() == tinykvm::VmGroupHostGuard::Off);
	REQUIRE(group->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerGroup);
	REQUIRE(group->live_members() == GROUP_SIZE);

	/* A distinct pattern in every band, at both ends of it - the whole band is
	   writable in this mode, so both ends are part of the claim. */
	const uint64_t band_len = group->arena_stride() - forks[0]->seat()->arena_size;
	REQUIRE(band_len == tinykvm::VmGroup::GUARD_BAND);
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		char* const band = forks[i]->seat()->arena_hva + forks[i]->seat()->arena_size;
		const int pattern = BAND_BASE + int(i);
		memcpy(band, &pattern, sizeof(pattern));
		memcpy(band + band_len - sizeof(pattern), &pattern, sizeof(pattern));
	}

	const auto find_pattern = [&] (const char* begin, uint64_t len, int pattern) -> bool {
		for (uint64_t off = 0; off + sizeof(int) <= len; off += sizeof(int)) {
			int word = 0;
			memcpy(&word, begin + off, sizeof(word));
			if (word == pattern)
				return true;
		}
		return false;
	};

	/* Guest side: every member still reads its own value. Band dirt is not in
	   any member's partition, so no guest can see it. */
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		forks[i]->timed_vmcall(read_value, 4.0f);
		REQUIRE(forks[i]->return_value() == long(PATTERN_BASE + i));
	}
	/* Host side: each band holds its own pattern and nobody else's, and no
	   member's used partition holds a band pattern at all. */
	for (size_t i = 0; i < GROUP_SIZE; i++) {
		const auto* seat = forks[i]->seat();
		char* const band = seat->arena_hva + seat->arena_size;
		int word = 0;
		memcpy(&word, band, sizeof(word));
		REQUIRE(word == BAND_BASE + int(i));
		memcpy(&word, band + band_len - sizeof(word), sizeof(word));
		REQUIRE(word == BAND_BASE + int(i));

		const uint64_t used = forks[i]->main_memory().banks.partition_used();
		REQUIRE(used > 0);
		REQUIRE(find_pattern(seat->arena_hva, used, PATTERN_BASE + int(i)));
		for (size_t j = 0; j < GROUP_SIZE; j++) {
			REQUIRE(!find_pattern(seat->arena_hva, used, BAND_BASE + int(j)));
			if (j == i)
				continue;
			REQUIRE(!find_pattern(seat->arena_hva, used, PATTERN_BASE + int(j)));
		}
	}

	/* Recycle a seat. The scrub is clamped to arena_size, so the partition is
	   zeroed and the band is not: the new tenant starts from the master's state
	   with its predecessor's band dirt still sitting behind its partition. That is
	   not a leak between tenants - nothing maps the band into either of them - but
	   it is a fact about the lifetime of band dirt, and it is why the band is not
	   a place anything may be left. */
	char* const recycled = forks[1]->seat()->arena_hva;
	const uint64_t recycled_used = forks[1]->main_memory().banks.partition_used();
	const int recycled_id = forks[1]->seat()->kvm_vcpu_id;
	const uint64_t recycled_size = forks[1]->seat()->arena_size;
	REQUIRE(recycled_used > 0);
	forks[1].reset();

	for (uint64_t off = 0; off < recycled_used; off += 512)
		REQUIRE(recycled[off] == 0);
	int band_word = 0;
	memcpy(&band_word, recycled + recycled_size, sizeof(band_word));
	REQUIRE(band_word == BAND_BASE + 1);

	tinykvm::Machine tenant { machine, options };
	REQUIRE(tenant.seat()->kvm_vcpu_id == recycled_id);
	REQUIRE(tenant.seat()->arena_hva == recycled);
	tenant.timed_vmcall(read_value, 4.0f);
	REQUIRE(tenant.return_value() == 0);
	/* Also high-entropy, and for the same reason: it is searched for negatively
	   across every sibling's partition at the end of this case. */
	static constexpr int TENANT_PATTERN = 0x5EA7C0DE;
	tenant.timed_vmcall(set_value, 4.0f, TENANT_PATTERN);
	REQUIRE(tenant.return_value() == TENANT_PATTERN);
	memcpy(&band_word, recycled + recycled_size, sizeof(band_word));
	REQUIRE(band_word == BAND_BASE + 1);

	/* And the siblings are untouched by any of it. */
	for (size_t j = 0; j < GROUP_SIZE; j++) {
		if (j == 1)
			continue;
		forks[j]->timed_vmcall(read_value, 4.0f);
		REQUIRE(forks[j]->return_value() == long(PATTERN_BASE + j));
		REQUIRE(!find_pattern(forks[j]->seat()->arena_hva,
			forks[j]->main_memory().banks.partition_used(), TENANT_PATTERN));
	}
}

TEST_CASE("The arena memslot's geometry and alignment", "[VmGroup]")
{
	/* I1/I2 make one slot possible; I6 is what makes it safe. With the whole span
	   in one memslot, KVM may build a 2 MiB EPT leaf anywhere inside it whenever
	   the window is hugepage-backed, and a leaf straddling a seat boundary would
	   map a slice of a sibling's memory into this member. Under PerSeat the slot
	   boundary guaranteed that could not happen; under PerGroup it is an alignment
	   argument, so this is where the argument is checked. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const uint64_t huge = tinykvm::VmGroup::HUGEPAGE_ALIGNMENT;
	/* The constants the static_assert in vm_group.hpp covers, restated so a
	   failure here names the property rather than a translation unit. */
	REQUIRE(tinykvm::VmGroup::GUARD_BAND % huge == 0);
	REQUIRE(tinykvm::VmGroup::BANK_ALIGNMENT % huge == 0);

	SECTION("PerGroup: one slot, the whole span, every boundary 2 MiB-aligned") {
		const auto options = pooled_options(tinykvm::VmGroupArenaSlot::PerGroup);
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (size_t i = 0; i < GROUP_SIZE; i++)
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));

		const auto* group = forks[0]->group();
		const size_t base_slots =
			tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
		REQUIRE(group->arena_slot() == base_slots);
		/* The slot covers the group's whole guest-physical span - every seat's
		   partition and every band between them - and is the same one for all. */
		REQUIRE(group->arena_span() == uint64_t(group->capacity()) * group->arena_stride());
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			REQUIRE(forks[i]->group() == group);
			REQUIRE(forks[i]->seat()->memslot == group->arena_slot());
		}

		/* I6, on the values this group actually got. */
		REQUIRE(group->arena_base() % tinykvm::VmGroup::BANK_ALIGNMENT == 0);
		REQUIRE(group->arena_base() % huge == 0);
		REQUIRE(uintptr_t(group->arena_hva()) % huge == 0);
		REQUIRE(group->arena_stride() % huge == 0);
		for (unsigned i = 0; i < group->capacity(); i++) {
			const uint64_t partition = group->arena_base()
				+ uint64_t(i) * group->arena_stride();
			const uint64_t band = partition
				+ (group->arena_stride() - tinykvm::VmGroup::GUARD_BAND);
			/* Both boundaries of every partition, materialized or not: no 2 MiB
			   leaf inside the span can straddle either of them. */
			REQUIRE(partition % huge == 0);
			REQUIRE(band % huge == 0);
		}
		/* And the affine relation the single slot rests on, per seat. */
		const uint64_t delta = group->arena_base() - uintptr_t(group->arena_hva());
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			const auto* seat = forks[i]->seat();
			REQUIRE(seat->arena_gpa - uintptr_t(seat->arena_hva) == delta);
			REQUIRE(seat->arena_gpa >= group->arena_base());
			REQUIRE(seat->arena_gpa + group->arena_stride()
				<= group->arena_base() + group->arena_span());
		}
	}

	SECTION("PerSeat: a slot per seat, in materialization order") {
		const auto options = pooled_options(tinykvm::VmGroupArenaSlot::PerSeat);
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (size_t i = 0; i < GROUP_SIZE; i++)
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));

		const auto* group = forks[0]->group();
		const size_t base_slots =
			tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
		for (size_t i = 0; i < GROUP_SIZE; i++) {
			const auto* seat = forks[i]->seat();
			/* Seats are materialized in index order and take slots in the same
			   order, so the seat's own id gives its slot. */
			REQUIRE(seat->memslot == base_slots + uint64_t(seat->kvm_vcpu_id));
		}
	}
}

TEST_CASE("The arena slot mode is part of group eligibility", "[VmGroup]")
{
	/* The mode decides how the arena's memslots are *installed*, so like the host
	   guard mode it cannot be retrofitted onto a group that already exists: a
	   PerSeat member in a PerGroup group would be counting on a slot of its own
	   that nobody installed (and would have a backed guard band), and a PerGroup
	   member in a PerSeat group would be counting on a whole-span slot that does
	   not exist. A mismatch therefore has to mean "open a new group" rather than
	   "this fork cannot be built" - refusing here would be a permanent
	   create_fork() outage for this master. Unlike the guard mode there is no Auto
	   to match anything: the comparison is plain equality both ways. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	/* The guard mode is pinned in both groups, so the only thing that can differ
	   between them is the slot mode. Left as Auto it would resolve from the
	   kernel version and the build's NDEBUG, and the "mixed" case at the end -
	   which asks for a guard mode explicitly - could then match or mismatch by
	   accident rather than by the property under test. */
	const auto per_group_options = pooled_options(tinykvm::VmGroupHostGuard::Off,
		tinykvm::VmGroupArenaSlot::PerGroup);
	const auto per_seat_options = pooled_options(tinykvm::VmGroupHostGuard::Off,
		tinykvm::VmGroupArenaSlot::PerSeat);

	tinykvm::Machine per_group { machine, per_group_options };
	per_group.timed_vmcall(get_value, 4.0f);
	REQUIRE(per_group.return_value() == 1);
	const auto* group_a = per_group.group();
	REQUIRE(group_a->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerGroup);
	REQUIRE(machine.groups().group_count() == 1);
	REQUIRE(group_a->capacity() > 1); /* A has room, so only the mode can refuse */

	/* A PerSeat member cannot have A's arena, so a second group opens even though
	   A is nowhere near full. */
	tinykvm::Machine per_seat { machine, per_seat_options };
	per_seat.timed_vmcall(get_value, 4.0f);
	REQUIRE(per_seat.return_value() == 1);
	const auto* group_b = per_seat.group();
	REQUIRE(group_b != group_a);
	REQUIRE(group_b->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerSeat);
	REQUIRE(machine.groups().group_count() == 2);
	REQUIRE(group_a->live_members() == 1);

	/* And the other way round, which is the half a default-valued field makes easy
	   to get wrong: a second member of each mode joins its own group rather than
	   opening a third. */
	tinykvm::Machine per_group_two { machine, per_group_options };
	REQUIRE(per_group_two.group() == group_a);
	tinykvm::Machine per_seat_two { machine, per_seat_options };
	REQUIRE(per_seat_two.group() == group_b);
	REQUIRE(machine.groups().group_count() == 2);

	/* The two modes are independent of the guard mode: a member asking for a
	   different (guard, slot) pair than either group has opens a third group,
	   even though group A already matches its slot mode. */
	tinykvm::Machine mixed { machine,
		pooled_options(tinykvm::VmGroupHostGuard::Mprotect,
			tinykvm::VmGroupArenaSlot::PerGroup) };
	REQUIRE(mixed.group() != group_a);
	REQUIRE(mixed.group() != group_b);
	REQUIRE(mixed.group()->arena_slot_mode() == tinykvm::VmGroupArenaSlot::PerGroup);
	REQUIRE(mixed.group()->host_guard() == tinykvm::VmGroupHostGuard::Mprotect);
	REQUIRE(machine.groups().group_count() == 3);
}

TEST_CASE("A pooled member cannot install or delete a memslot", "[VmGroup]")
{
	/* Every memslot of a pooled member's VM belongs to the group and is shared
	   with every sibling, and the slot index would come from this member's own
	   bank allocator - which starts at FIRST_BANK_IDX and would therefore land on
	   the group's first mmap-range slot or on its arena slot, replacing (or, for
	   a deletion, removing) a region every sibling is running out of. Nothing in
	   the tree reaches this today, which is the point: the refusal is what makes
	   "a live group performs no memslot operations" executable rather than
	   conventional, and it is the pooled analogue of the mmap_backed_area and
	   reset-to-new-master refusals. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	/* A page of host memory at a guest-physical address no part of the layout
	   uses: above main memory, below MMAP_PHYS_BASE and far below the arena. */
	static constexpr uint64_t FREE_GPA = 0x2000000000ULL; /* 128 GiB */
	static constexpr uint32_t FREE_SLOT = 200;
	const size_t page = tinykvm::vMemory::PageSize();
	char* const scratch = (char *) mmap(nullptr, page, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	REQUIRE(scratch != MAP_FAILED);
	const tinykvm::VirtualMem vmem { FREE_GPA, scratch, page };

	tinykvm::Machine fork { machine, pooled_options() };
	REQUIRE(fork.is_pooled());
	const uint64_t ops_before = tinykvm::VmGroup::memslot_ops();
	REQUIRE_THROWS_AS(fork.install_memory(FREE_SLOT, vmem, false),
		tinykvm::MachineException);
	REQUIRE_THROWS_AS(fork.delete_memory(FREE_SLOT), tinykvm::MachineException);
	/* Refused before the ioctl, not by it: no memslot operation happened. */
	REQUIRE(tinykvm::VmGroup::memslot_ops() == ops_before);

	/* Positive control on the same call with the same arguments: what is refused
	   is being pooled, not the region. The master owns its VM, so it may. */
	REQUIRE(!machine.is_pooled());
	REQUIRE_NOTHROW(machine.install_memory(FREE_SLOT, vmem, false));
	REQUIRE_NOTHROW(machine.delete_memory(FREE_SLOT));
	REQUIRE(tinykvm::VmGroup::memslot_ops() == ops_before + 2);

	/* The member is unharmed by the refusals. */
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);
	munmap(scratch, page);
}

/* Hidden (leading-dot tag): a timing probe, not an assertion. Run manually with
   `./vm_group "[memslot-probe]"`. The attribution artifact for phase 6, and the
   one that needs no load generator: KVM_SET_USER_MEMORY_REGION ends in
   synchronize_srcu_expedited(&kvm->srcu), whose cost grows with the number of
   vCPUs registered in that struct kvm - so under PerSeat the k-th seat of a group
   is measurably dearer to materialize than the first, and the cost of a seat is a
   *slope* against seat index rather than a constant. Under PerGroup there is no
   memslot operation at all, so the same measurement is flat. Reported as a
   least-squares slope in ns per seat index, which is the number that should
   collapse. */
TEST_CASE("PROBE: per-seat materialization cost against seat index", "[.][memslot-probe]")
{
	tinykvm::Machine::init(); /* the [Initialize] case is filtered out here */
	const auto binary = group_test_binary();

	/* As many seats as the host's vCPU wall allows, up to 512: the SRCU term the
	   probe is looking for is a slope against seat index, so the lever arm is the
	   measurement. */
	const unsigned SEATS = std::min<unsigned>(512,
		tinykvm::KvmLimits::get().max_vcpus - tinykvm::VmGroup::VCPU_HEADROOM);
	const auto measure = [&] (const char* label, tinykvm::VmGroupArenaSlot slot) {
		/* The master lives inside the measurement, so that its VmGroupSet - and
		   with it the group, and with the group SEATS vCPU fds - is gone before the
		   next one starts. A shared master would keep the first pass's group as the
		   warm spare (whole-group retirement hysteresis keeps one), and the second
		   pass would then run with ~2*SEATS vCPU fds open: at SEATS=512 that is over
		   the usual 1024 soft RLIMIT_NOFILE, and KVM_CREATE_VCPU would start failing
		   with EMFILE in the middle of the arm being measured. Cheap: one guest
		   build is shared, only setup_linux and the CoW snapshot are repeated. */
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
		machine.setup_linux({"group"}, env);
		machine.run(4.0f);
		machine.prepare_copy_on_write(65536);
		/* And the proof that it worked, before anything is allocated: whatever this
		   process holds now, it is not the previous arm's seats. */
		REQUIRE(count_kvm_vcpus() < SEATS);

		/* One group of SEATS seats, filled once and held: every member
		   materializes a fresh seat, so member k's construction is seat index k's
		   materialization. Nothing is run - the point is the cost of appearing,
		   not of executing - and the kvm_run mapping is left lazy so the only
		   per-seat host work in the window is the memslot install itself. */
		auto options = pooled_options(tinykvm::VmGroupHostGuard::Off, slot);
		options.vm_group_size = SEATS;
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		forks.reserve(SEATS);
		std::vector<double> us(SEATS, 0.0);
		for (unsigned i = 0; i < SEATS; i++) {
			const auto t0 = std::chrono::steady_clock::now();
			forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
			const auto t1 = std::chrono::steady_clock::now();
			us[i] = std::chrono::duration<double, std::micro>(t1 - t0).count();
		}
		REQUIRE(forks[0]->group()->capacity() >= SEATS);
		REQUIRE(forks[SEATS - 1]->group() == forks[0]->group());
		REQUIRE(forks[0]->group()->arena_slot_mode() == slot);

		/* The slope is fitted over the last three quarters only. The first
		   iterations pay for the allocator's and the master's first-touch costs,
		   which have nothing to do with seat index and which bias a whole-range
		   fit downwards; the quarter means are printed alongside so that bias is
		   visible rather than hidden. */
		const unsigned skip = SEATS / 4;
		double sx = 0, sy = 0, sxx = 0, sxy = 0, total = 0;
		for (unsigned i = 0; i < SEATS; i++) {
			total += us[i];
			if (i < skip)
				continue;
			sx += i; sy += us[i]; sxx += double(i) * i; sxy += double(i) * us[i];
		}
		const double n = SEATS - skip;
		const double slope = (n * sxy - sx * sy) / (n * sxx - sx * sx);
		double first = 0, last = 0;
		for (unsigned i = 0; i < skip; i++) {
			first += us[i];
			last  += us[SEATS - 1 - i];
		}
		first /= skip;
		last  /= skip;
		printf("PROBE %-10s mean %7.1f us  first-quarter %7.1f  last-quarter %7.1f"
			"  tail slope %+7.1f ns/seat-index  (%u seats)\n",
			label, total / SEATS, first, last, slope * 1000.0, SEATS);
		fflush(stdout);
	};
	measure("perseat", tinykvm::VmGroupArenaSlot::PerSeat);
	measure("pergroup", tinykvm::VmGroupArenaSlot::PerGroup);
	REQUIRE(true);
}
