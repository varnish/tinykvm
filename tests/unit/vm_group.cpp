#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <atomic>
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
	/* Groups outlive their members (whole-group retirement is Phase 2). */
	REQUIRE(count_kvm_vms() == baseline + 2);
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
	   no second group appears and every member behaves identically. */
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
