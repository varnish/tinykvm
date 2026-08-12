#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/smp.hpp>
#include <cstdio>
#include <cstring>
#include <linux/kvm.h> /* struct kvm_sregs */
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const uint64_t MAX_COWMEM = 3ul << 20; /* 3MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

/* Every mmap'ed kvm_run page is one non-coalescible VMA in this address
   space, which every later KVM_CREATE_VM has to walk and lock. With lazy
   mapping there must be exactly one for each vCPU that has *ever run*, not
   one for each vCPU that exists. This is the check that proves the lazy
   mapping engaged at all. */
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

/* A pooled fork's kvm_run mapping belongs to its VM group *seat*, which outlives
   every tenant on purpose: the next member of that seat inherits the mapping and
   does not pay lever C's one-time flip again. So under
   -DTINYKVM_VM_GROUP_DEFAULT=true (the compile-time A/B of the pooled path) the
   mapping count does not return to its baseline when the forks are destroyed -
   it returns to it when the *group* is retired, which the retirement policy
   deliberately delays (one empty group is kept as a warm spare). Detected from
   the option default rather than the macro, so this stays correct whichever way
   the default is set. */
static bool pooling_is_default()
{
	return tinykvm::MachineOptions{}.vm_group;
}

static tinykvm::MachineOptions lazy_options()
{
	tinykvm::MachineOptions options;
	options.max_mem = MAX_MEMORY;
	options.max_cow_mem = MAX_COWMEM;
	options.lazy_vcpu_mmap = true;
	return options;
}

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

static std::vector<uint8_t> lazy_test_binary()
{
	return build_and_load(R"M(
int main() {
}

static int value = 0;
extern int get_value() {
	value ++;
	return value;
}
extern int add_values(int a, int b) {
	return a + b;
})M");
}

TEST_CASE("Lazily mapped fork never runs", "[LazyRun]")
{
	const auto binary = lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	/* The master is always mapped eagerly. */
	const size_t baseline = count_vcpu_mappings();
	REQUIRE(baseline > 0);

	/* Constructed and destroyed without ever running. */
	{
		tinykvm::Machine fork { machine, lazy_options() };
		REQUIRE(fork.is_forked());
		REQUIRE(count_vcpu_mappings() == baseline);
	}
	REQUIRE(count_vcpu_mappings() == baseline);

	/* Reset and destroyed without ever running. reset_to() enters usermode,
	   which reads back the staged special registers. */
	{
		tinykvm::Machine fork { machine, lazy_options() };
		fork.reset_to(machine, lazy_options());
		REQUIRE(count_vcpu_mappings() == baseline);
		fork.reset_to(machine, lazy_options());
		REQUIRE(count_vcpu_mappings() == baseline);
	}
	REQUIRE(count_vcpu_mappings() == baseline);
}

TEST_CASE("Lazily mapped fork runs correctly", "[LazyRun]")
{
	const auto binary = lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_vcpu_mappings();
	const auto get_value = machine.address_of("get_value");
	const auto add_values = machine.address_of("add_values");
	REQUIRE(get_value != 0x0);
	REQUIRE(add_values != 0x0);

	tinykvm::Machine fork { machine, lazy_options() };
	/* The staged special registers must be readable (and correct) before the
	   mapping exists: the fork has its own page tables already. */
	const auto staged_cr3 = fork.get_special_registers().cr3;
	REQUIRE(staged_cr3 != 0x0);
	REQUIRE(staged_cr3 == fork.main_memory().page_tables);
	REQUIRE(count_vcpu_mappings() == baseline);

	/* First run: the mapping appears, and the staged registers have to
	   survive the transition, or the guest fails entry with CR3=0. */
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);
	REQUIRE(count_vcpu_mappings() == baseline + 1);
	REQUIRE(fork.get_special_registers().cr3 == staged_cr3);

	/* Later runs must not map anything more. */
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 2);
	fork.timed_vmcall(add_values, 4.0f, 10, 32);
	REQUIRE(fork.return_value() == 42);
	REQUIRE(count_vcpu_mappings() == baseline + 1);

	/* Reset, then run again. */
	fork.reset_to(machine, lazy_options());
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);
	REQUIRE(count_vcpu_mappings() == baseline + 1);
}

TEST_CASE("Lazily mapped fork resets before running", "[LazyRun]")
{
	const auto binary = lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_vcpu_mappings();
	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	tinykvm::Machine fork { machine, lazy_options() };
	for (int i = 0; i < 10; i++) {
		fork.reset_to(machine, lazy_options());
		REQUIRE(count_vcpu_mappings() == baseline);
	}
	/* Recycled while parked, then finally run. */
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 1);
	REQUIRE(count_vcpu_mappings() == baseline + 1);
}

TEST_CASE("Only forks that have run are mapped", "[LazyRun]")
{
	const auto binary = lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_vcpu_mappings();
	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	static constexpr size_t FORKS = 8;
	static constexpr size_t RUN   = 3;
	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < FORKS; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, lazy_options()));
	}
	REQUIRE(count_vcpu_mappings() == baseline);

	for (size_t i = 0; i < RUN; i++) {
		forks[i]->timed_vmcall(get_value, 4.0f);
		REQUIRE(forks[i]->return_value() == 1);
	}
	/* One mapping per fork that has ever run, and running twice adds none. */
	REQUIRE(count_vcpu_mappings() == baseline + RUN);
	forks[0]->timed_vmcall(get_value, 4.0f);
	REQUIRE(forks[0]->return_value() == 2);
	REQUIRE(count_vcpu_mappings() == baseline + RUN);

	forks.clear();
	if (pooling_is_default()) {
		/* The RUN mappings stay with the seats of the (retained) group. */
		REQUIRE(count_vcpu_mappings() == baseline + RUN);
	} else {
		REQUIRE(count_vcpu_mappings() == baseline);
	}
}

TEST_CASE("Eagerly mapped forks map at construction", "[LazyRun]")
{
	/* Control for the counting above: without the option, every fork maps
	   its kvm_run page during construction. */
	const auto binary = lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const size_t baseline = count_vcpu_mappings();
	tinykvm::MachineOptions options = lazy_options();
	options.lazy_vcpu_mmap = false;

	std::vector<std::unique_ptr<tinykvm::Machine>> forks;
	for (size_t i = 0; i < 4; i++) {
		forks.push_back(std::make_unique<tinykvm::Machine> (machine, options));
	}
	REQUIRE(count_vcpu_mappings() == baseline + 4);

	const auto get_value = machine.address_of("get_value");
	forks[0]->timed_vmcall(get_value, 4.0f);
	REQUIRE(forks[0]->return_value() == 1);
	REQUIRE(count_vcpu_mappings() == baseline + 4);

	forks.clear();
	if (pooling_is_default()) {
		/* Eagerly mapped seats keep all four mappings for their next tenants. */
		REQUIRE(count_vcpu_mappings() == baseline + 4);
	} else {
		REQUIRE(count_vcpu_mappings() == baseline);
	}
}

/* Regression tests for the SMP x lazy-kvm_run interaction (fast-agent issue
   #19). docs/design/create-fork-vm-pooling.md's lever C states the lazy
   mapping is per-vCPU bookkeeping ("map = #forks that have ever run", the
   invariant `Only forks that have run are mapped` above already locks in for
   single-vCPU forks); this exercises the same bookkeeping once a fork itself
   goes SMP (real multi-vCPU via Machine::smp(), not the cooperative
   MultiThreading green threads used for guest pthread emulation).

   SMP is AMD64-only in this tree today (lib/tinykvm/arm64/stubs.cpp:
   Machine::smp() throws "SMP is not implemented on ARM64"), so this file
   builds only under TINYKVM_ARCH=AMD64 already (see CMakeLists.txt) and
   there is no ARM64 counterpart to add. */

static std::vector<uint8_t> smp_lazy_test_binary()
{
	return build_and_load(R"M(
int main() {
}
static volatile long counter = 0;
extern void bump() {
	__sync_fetch_and_add(&counter, 1);
}
extern long get_counter() {
	return counter;
})M");
}

TEST_CASE("SMP fork lazily maps its main vCPU and eagerly maps the SMP vCPUs it brings up", "[LazyRun][SMP]")
{
	/* Give the *master* more than one real vCPU (via Machine::smp(), not
	   guest-level threading) before it is snapshotted. Nothing in the design
	   doc's lever C claims a master's own vCPU history changes anything
	   about a fork's lazy main-vCPU mapping -- a fork always starts with
	   exactly one vCPU (guest_cpu_index 0) regardless of what the master
	   used, so this proves that holds even when the master itself went SMP. */
	const auto binary = smp_lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy_smp"}, env);
	machine.run(4.0f);

	const auto bump = machine.address_of("bump");
	const auto get_counter = machine.address_of("get_counter");
	REQUIRE(bump != 0x0);
	REQUIRE(get_counter != 0x0);

	{
		const uint64_t master_stack = machine.mmap_allocate(3 * 0x4000);
		machine.smp().timed_smpcall(2, master_stack, 0x4000, bump, 4.0f);
		machine.smp_wait();
		REQUIRE(machine.smp_active_count() == 0);
	}

	machine.prepare_copy_on_write(65536);

	/* Baseline is captured *after* the master's own SMP run, so it already
	   contains the master's own (always-eager) vCPU mappings -- what matters
	   below is the delta the fork itself introduces. */
	const size_t baseline = count_vcpu_mappings();

	tinykvm::Machine fork { machine, lazy_options() };

	/* (a) Construction maps nothing: not the fork's own main vCPU, and
	   nothing about the master's SMP history forced anything either. */
	REQUIRE(count_vcpu_mappings() == baseline);

	/* First use of the fork's own main vCPU maps exactly one kvm_run page. */
	fork.timed_vmcall(get_counter, 4.0f);
	REQUIRE(fork.return_value() == 2); /* inherited from the master's two bumps */
	REQUIRE(count_vcpu_mappings() == baseline + 1);

	/* (b) Bring up the fork's own SMP vCPUs and use every one of them. */
	static constexpr size_t SMP_CPUS = 3;
	const uint64_t fork_stack = fork.mmap_allocate((SMP_CPUS + 1) * 0x4000);
	fork.smp().timed_smpcall(SMP_CPUS, fork_stack, 0x4000, bump, 4.0f);
	fork.smp_wait();
	REQUIRE(fork.smp_active_count() == 0);

	fork.timed_vmcall(get_counter, 4.0f);
	REQUIRE(fork.return_value() == 2 + (long)SMP_CPUS);

	/* Secondary SMP vCPUs are only ever created in order to run immediately
	   (vCPU::smp_init maps kvm_run eagerly at creation, unlike the lazily
	   mapped main vCPU above -- "SMP vCPUs are only ever created in order to
	   run", per the comment at their creation site), so bringing up SMP_CPUS
	   of them adds exactly that many mappings: one per vCPU that has ever
	   existed on this fork, main included. */
	REQUIRE(count_vcpu_mappings() == baseline + 1 + SMP_CPUS);
}

TEST_CASE("SMP fork teardown releases every per-vCPU kvm_run mapping", "[LazyRun][SMP]")
{
	const auto binary = smp_lazy_test_binary();
	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"lazy_smp"}, env);
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto bump = machine.address_of("bump");
	const auto get_counter = machine.address_of("get_counter");
	REQUIRE(bump != 0x0);
	REQUIRE(get_counter != 0x0);

	const size_t baseline = count_vcpu_mappings();
	static constexpr size_t SMP_CPUS = 2;

	{
		tinykvm::Machine fork { machine, lazy_options() };
		fork.timed_vmcall(get_counter, 4.0f); /* main vCPU: +1 mapping */

		const uint64_t stack = fork.mmap_allocate((SMP_CPUS + 1) * 0x4000);
		fork.smp().timed_smpcall(SMP_CPUS, stack, 0x4000, bump, 4.0f);
		fork.smp_wait();
		REQUIRE(fork.smp_active_count() == 0);
		REQUIRE(count_vcpu_mappings() == baseline + 1 + SMP_CPUS);

		/* A reset recycles the same vCPUs in place -- "never unmap on park"
		   (Term 3 in the design doc: unmapping on park would cost an O(N)
		   invalidate fan-out plus a TLB shootdown for nothing, since the next
		   tenant just remaps it). Every mapping this fork has ever created
		   survives the reset. */
		fork.reset_to(machine, lazy_options());
		REQUIRE(count_vcpu_mappings() == baseline + 1 + SMP_CPUS);

		fork.timed_vmcall(get_counter, 4.0f);
		REQUIRE(fork.return_value() == 0); /* fresh master state: no bumps yet */
		REQUIRE(count_vcpu_mappings() == baseline + 1 + SMP_CPUS);
	}
	/* Only real teardown (~Machine) releases every per-vCPU mapping the fork
	   ever created -- main and every SMP vCPU alike. */
	REQUIRE(count_vcpu_mappings() == baseline);
}
