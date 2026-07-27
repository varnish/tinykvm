#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/paging.hpp>
#include <tinykvm/smp.hpp>
#include <tinykvm/amd64/amd64.hpp>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <memory>
#include <stdexcept>
#include <string>
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

static tinykvm::MachineOptions pooled_options()
{
	tinykvm::MachineOptions options;
	options.max_mem = MAX_MEMORY;
	options.max_cow_mem = MAX_COWMEM;
	options.vm_group = true;
	options.vm_group_size = GROUP_SIZE;
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
	/* Seat windows are adjacent in the host address space, so a GPA-only
	   guard band would let a host-side linear overrun (page_duplicate() or a
	   memcpy() walking off the end of the last bank) land silently in a
	   sibling's guest memory - where an unpooled VM's standalone bank mmap
	   would have SIGSEGV'd. The stride is reserved whole and only the usable
	   part is made accessible. */
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
	/* One memslot per seat covering its whole partition, plus the group's
	   shared base slots (main memory, the reserved remote slot, and one per
	   master mmap range). KVM_CAP_NR_MEMSLOTS is 32764 on current hosts so it
	   does not bind here, but it is a real wall and MemoryBank::idx is a
	   uint16_t. */
	const auto binary = group_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"group"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	auto options = pooled_options();
	options.vm_group_size = 0; /* let the group pick B from the host's walls */
	tinykvm::Machine fork { machine, options };
	const auto* group = fork.group();
	const auto& limits = tinykvm::KvmLimits::get();

	const size_t base_slots =
		tinykvm::VmGroup::BASE_MEMSLOTS + group->mmap_range_count();
	REQUIRE(group->capacity() + base_slots <= limits.nr_memslots);
	REQUIRE(group->capacity() + base_slots <= 0xFFFFu);
	/* And the vCPU count wall, which is per struct kvm. */
	REQUIRE(group->capacity() + tinykvm::VmGroup::VCPU_HEADROOM <= limits.max_vcpus);
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
