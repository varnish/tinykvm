#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const uint64_t MAX_COWMEM = 3ul << 20; /* 1MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

TEST_CASE("Execute function in fork", "[Fork]")
{
	bool output_is_hello_world = false;
	const auto binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
}
extern void prints_hello_world() {
	write(1, "Hello World!", 12);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"fork"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	REQUIRE(machine.banked_memory_pages() == 0);

	// write syscall not called yet
	REQUIRE(!output_is_hello_world);

	// Make machine forkable (no working memory)
	machine.prepare_copy_on_write(65536);
	REQUIRE(machine.banked_memory_pages() == 5);
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	fork.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		output_is_hello_world = (text == "Hello World!");
	});
	REQUIRE(fork.banked_memory_pages() > 0);
	const auto n = fork.banked_memory_pages();

	// write syscall not called yet
	REQUIRE(!output_is_hello_world);

	auto funcaddr = fork.address_of("prints_hello_world");
	REQUIRE(funcaddr != 0x0);

	fork.timed_vmcall(funcaddr, 4.0f);
	// Calling into the forked VM added a few more banked pages
	// Around 32kb at the time of writing this.
	REQUIRE(fork.banked_memory_pages() > n);

	// Now the output should be written out
	REQUIRE(output_is_hello_world);
}

TEST_CASE("Fork and run out of memory", "[Fork]")
{
	const auto binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
}
extern void callable_function() {
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"fork"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);

	// Make machine forkable
	machine.prepare_copy_on_write();
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	REQUIRE_THROWS([&] () {
		// Create fork that runs out of memory
		tinykvm::MachineOptions options;
		options.max_mem = MAX_MEMORY;
		options.max_cow_mem = 0UL;
		tinykvm::Machine fork { machine, options};
	}());
}

TEST_CASE("Execute function in forkable VM", "[Fork]")
{
	bool output_is_hello_world = false;
	const auto binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
}
extern void prints_hello_world() {
	write(1, "Hello World!", 12);
})M");

	tinykvm::Machine machine { binary, {
		.max_mem = MAX_MEMORY,
		.split_hugepages = true
	 } };
	machine.setup_linux({"fork"}, env);
	machine.run(4.0f);

	REQUIRE(machine.banked_memory_pages() == 0);

	// write syscall not called yet
	REQUIRE(!output_is_hello_world);
	machine.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		output_is_hello_world = (text == "Hello World!");
	});

	// Make machine forkable
	machine.prepare_copy_on_write(1UL << 20);
	REQUIRE(machine.banked_memory_pages() > 0);
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };
	REQUIRE(fork.banked_memory_pages() > 0);

	auto funcaddr = machine.address_of("prints_hello_world");
	REQUIRE(funcaddr != 0x0);

	// Handler not called yet
	fork.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(!output_is_hello_world);

	// Now the output should be written out
	machine.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(output_is_hello_world);
	//fprintf(stderr, "Banked pages: %zu\n", machine.banked_memory_pages());
}

TEST_CASE("Fork sanity checks", "[Fork]")
{
	const auto binary = build_and_load(R"M(
#include <assert.h>
int main() {
}

static int value = 0;
extern int get_value() {
	value ++;
	return value;
}

extern void crash() {
	assert(0);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"fork"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	REQUIRE(machine.banked_memory_pages() == 0);

	// Make machine forkable (with working memory)
	machine.prepare_copy_on_write(0);
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Create fork
	auto fork1 = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	auto fork2 = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	auto funcaddr = machine.address_of("get_value");
	REQUIRE(funcaddr != 0x0);

	fork1.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork1.return_value() == 1);

	fork2.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork2.return_value() == 1);

	fork1.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork1.return_value() == 2);

	fork2.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork2.return_value() == 2);

	fork1.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM,
	});

	fork2.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM,
	});

	fork1.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork1.return_value() == 1);

	fork2.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork2.return_value() == 1);

	// The main VM is not executable due to no working memory
	REQUIRE_THROWS([&] () {
		machine.timed_vmcall(funcaddr, 4.0f);
	}());
}

TEST_CASE("Fork w/working memory sanity checks", "[Fork]")
{
	const auto binary = build_and_load(R"M(
#include <assert.h>
int main() {
}

static int value = 0;
extern int get_value() {
	value ++;
	return value;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY,
		.split_hugepages = true
	 } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"fork"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	REQUIRE(machine.banked_memory_pages() == 0);

	// Make machine forkable (with working memory)
	machine.prepare_copy_on_write(65536);
	REQUIRE(machine.banked_memory_pages() == 5);
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Create fork
	auto fork1 = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };
	auto fork2 = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	auto funcaddr = machine.address_of("get_value");
	REQUIRE(funcaddr != 0x0);

	fork1.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork1.return_value() == 1);

	fork2.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork2.return_value() == 1);

	fork1.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork1.return_value() == 2);

	fork2.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(fork2.return_value() == 2);

	// The main VM is executable due to working memory
	machine.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(machine.return_value() == 1);

	for (int i = 0; i < 20; i++) {
		// Resetting will use the current state of the main VM
		fork1.reset_to(machine, {
				.max_mem = MAX_MEMORY,
				.max_cow_mem = MAX_COWMEM,
				.split_hugepages = true
		});

		fork2.reset_to(machine, {
				.max_mem = MAX_MEMORY,
				.max_cow_mem = MAX_COWMEM,
				.split_hugepages = true
		});

		// Value now starts at 1 due to the change in main VM
		fork1.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork1.return_value() == 1);

		fork2.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork2.return_value() == 1);

		fork1.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork1.return_value() == 2);

		fork2.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork2.return_value() == 2);
	}

	for (int i = 0; i < 20; i++) {
		// Resetting will use the current state of the main VM
		// but keep all working memory. This is still a reset, as
		// the original pages are still copied to the forked VM.
		// This type of reset will unfortunately only be able to see
		// working memory pages on the main VM, which means that when
		// we reset we see that the value starts at 1, and not 0,
		// because the main VM has made changes since it was prepared
		// for copy-on-write.
		fork1.reset_to(machine, {
				.max_mem = MAX_MEMORY,
				.max_cow_mem = MAX_COWMEM,
				.reset_keep_all_work_memory = true,
		});

		fork2.reset_to(machine, {
				.max_mem = MAX_MEMORY,
				.max_cow_mem = MAX_COWMEM,
				.reset_keep_all_work_memory = true,
		});

		// Value now starts at 1 due to the change in main VM
		fork1.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork1.return_value() == 1);

		fork2.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork2.return_value() == 1);

		fork1.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork1.return_value() == 2);

		fork2.timed_vmcall(funcaddr, 4.0f);
		REQUIRE(fork2.return_value() == 2);
	}
}

TEST_CASE("Fork sanity checks w/crashes", "[Fork]")
{
	const auto binary = build_and_load(R"M(
#include <assert.h>
int main() {
}

extern int normal() {
	return 42;
}
extern void crash() {
	assert(0);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"fork"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	REQUIRE(machine.banked_memory_pages() == 0);

	// Make machine forkable (with *NO* working memory)
	machine.prepare_copy_on_write(0);
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Create fork
	auto fork1 = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	auto funcaddr = machine.address_of("crash");
	REQUIRE(funcaddr != 0x0);

	auto normalfunc = machine.address_of("normal");
	REQUIRE(normalfunc != 0x0);

	fork1.timed_vmcall(normalfunc, 4.0f);
	REQUIRE(fork1.return_value() == 42);

	REQUIRE_THROWS([&] () {
		fork1.timed_vmcall(funcaddr, 4.0f);
	}());

	for (int i = 0; i < 20; i++)
	{
		fork1.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM,
		});

		fork1.timed_vmcall(normalfunc, 4.0f);
		REQUIRE(fork1.return_value() == 42);

		REQUIRE_THROWS([&] () {
			fork1.timed_vmcall(funcaddr, 4.0f);
		}());
	}

	for (int i = 0; i < 20; i++)
	{
		// This time reset, but keep all working memory
		// instead of resetting pagetables. This is still
		// a reset, as the original pages are still copied
		// to the forked VM.
		fork1.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM,
			.reset_keep_all_work_memory = true,
		});
		REQUIRE(fork1.banked_memory_pages() > 0);

		fork1.timed_vmcall(normalfunc, 4.0f);
		REQUIRE(fork1.return_value() == 42);

		REQUIRE_THROWS([&] () {
			fork1.timed_vmcall(funcaddr, 4.0f);
		}());
	}
}

TEST_CASE("Fork and run main()", "[Fork]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
int main() {
	printf("Hello World!\n");
	return 666;
}
static unsigned value = 12345;
void set_value(int v) {
	value = v;
}
int func1() {
	return value;
}
int func2() {
	return 54321;
}
)M");

	tinykvm::Machine machine { binary, {
		.max_mem = MAX_MEMORY,
		.master_direct_memory_writes = true
	} };

	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"fork"}, env);
	REQUIRE(machine.banked_memory_pages() == 0);

	// Make machine forkable (with 4MB working memory)
	machine.prepare_copy_on_write(4ULL << 20);
	REQUIRE(machine.banked_memory_capacity_bytes() == 4ULL << 20);
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	REQUIRE(machine.return_value() == 666); // Main() return value

	// We only gave it 4MB working memory, so lets mmap allocate that and verify
	// that if we write more than that, we get an exception thrown
	REQUIRE_THROWS([&] () {
		const size_t size = 8ULL << 20;
		uint64_t addr = machine.mmap_allocate(size);
		char buffer[4096];
		memset(buffer, 'a', sizeof(buffer));
		for (size_t i = 0; i < size; i += 4096)
		{
			machine.copy_to_guest(addr + i, buffer, 4096);
		}
		// Unreachable
		abort();
	}());

	// There are banked pages now
	const auto banked_pages_before = machine.main_memory().unlocked_memory_pages();
	REQUIRE(banked_pages_before > 500);

	// We have no free memory now, so make another VM
	tinykvm::Machine machine2 { binary, {
		.max_mem = MAX_MEMORY,
		.master_direct_memory_writes = true
	} };

	// We need to create a Linux environment for runtimes to work well
	machine2.setup_linux({"fork"}, env);
	REQUIRE(machine2.banked_memory_pages() == 0);

	// Make machine forkable (with 4MB working memory)
	machine2.prepare_copy_on_write(4ULL << 20);
	REQUIRE(machine2.banked_memory_capacity_bytes() == 4ULL << 20);
	REQUIRE(machine2.is_forkable());
	REQUIRE(!machine2.is_forked());

	// Run for at most 4 seconds before giving up
	machine2.run(4.0f);
	REQUIRE(machine2.return_value() == 666); // Main() return value

	machine2.prepare_copy_on_write(0);

	// Create fork
	auto fork1 = tinykvm::Machine { machine2, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	REQUIRE(fork1.return_value() == 666); // Main() return value

	fork1.vmcall("func1");
	REQUIRE(fork1.return_value() == 12345);

	fork1.vmcall("func2");
	REQUIRE(fork1.return_value() == 54321);
	REQUIRE(fork1.banked_memory_pages() > 0);

	for (int i = 0; i < 20; i++)
	{
		fork1.reset_to(machine2, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM,
		});

		fork1.vmcall("func1");
		REQUIRE(fork1.return_value() == 12345);

		fork1.vmcall("set_value", 22222);

		fork1.vmcall("func1");
		REQUIRE(fork1.return_value() == 22222);

		REQUIRE_THROWS([&] () {
			const size_t size = 8ULL << 20;
			uint64_t addr = fork1.mmap_allocate(size);
			char buffer[4096];
			memset(buffer, 'a', sizeof(buffer));
			for (size_t i = 0; i < size; i += 4096)
			{
				fork1.copy_to_guest(addr + i, buffer, 4096);
			}
			// Unreachable
			abort();
		}());

		auto fork2 = tinykvm::Machine { machine2, {
			.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
		} };
		REQUIRE(fork2.return_value() == 666); // Main() return value

		fork2.vmcall("func1");
		REQUIRE(fork2.return_value() == 12345);

		fork2.vmcall("set_value", 22222);

		fork2.vmcall("func1");
		REQUIRE(fork2.return_value() == 22222);
	}
}
