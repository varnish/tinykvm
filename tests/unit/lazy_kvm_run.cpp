#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
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
	REQUIRE(count_vcpu_mappings() == baseline);
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
	REQUIRE(count_vcpu_mappings() == baseline);
}
