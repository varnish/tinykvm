#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/linux/threads.hpp>
#include <cstring>
#include <linux/kvm.h> /* struct kvm_sregs */
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <unistd.h>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const uint64_t MAX_COWMEM = 3ul << 20; /* 3MB */
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
	// A fork's main vCPU is always guest-visible CPU 0, independent of its
	// KVM_CREATE_VCPU id (they only diverge under VM pooling).
	REQUIRE(fork.cpu().guest_cpu_index == 0);
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

TEST_CASE("foreach_memory spans non-contiguous host pages", "[Fork]")
{
	// Regression test for a bug in Machine::foreach_memory(): when an adjacent
	// guest page was backed by a non-contiguous host page, it emitted the
	// accumulated view but then reset the view to empty instead of restarting
	// it at the current page. Every byte from the first non-contiguous
	// transition onward was silently dropped.
	const auto binary = build_and_load(R"M(
volatile char buffer[16384];
char* get_buffer() { return (char*)buffer; }
int main() {
	for (int i = 0; i < 16384; i++) buffer[i] = 0;
})M");

	tinykvm::Machine machine { binary, {
		.max_mem = MAX_MEMORY,
		.split_hugepages = true
	} };
	machine.setup_linux({"fork"}, env);
	// Touch the buffer so its pages are backed by the master's memory before
	// we fork; cloned copy-on-write pages then resolve to real host memory.
	machine.run(4.0f);
	machine.prepare_copy_on_write(1UL << 20);

	// A fork uses copy-on-write banked memory, so freshly written pages are
	// backed by bank pages rather than the identity-mapped master memory.
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };
	REQUIRE(fork.uses_cow_memory());

	const size_t PAGE = tinykvm::vMemory::PageSize();
	// Page-align a 2-page window inside the guest's buffer.
	const uint64_t raw = fork.address_of("buffer");
	REQUIRE(raw != 0x0);
	const uint64_t addr = (raw + PAGE - 1) & ~(PAGE - 1);

	// Force the two adjacent guest pages onto NON-contiguous host pages:
	// allocate the second page's backing before the first page's. Bank pages
	// are handed out sequentially, so the second guest page ends up at a lower
	// host address than the first, and a forward scan hits a discontinuity at
	// the page boundary. Sub-page writes force a fresh bank page rather than
	// unlocking the (contiguous) source page in place.
	const std::string half(PAGE / 2, 'x');
	fork.copy_to_guest(addr + PAGE, half.data(), half.size());
	fork.copy_to_guest(addr,        half.data(), half.size());

	// Fill the whole 2-page range in place with a known pattern. The pages are
	// already present, so this keeps their (non-contiguous) host backing.
	std::string pattern(2 * PAGE, '\0');
	for (size_t i = 0; i < pattern.size(); i++)
		pattern[i] = char('A' + (i % 26));
	fork.copy_to_guest(addr, pattern.data(), pattern.size());

	// Collect every segment foreach_memory hands back.
	std::string captured;
	size_t segments = 0;
	fork.foreach_memory(addr, pattern.size(),
		[&] (std::string_view sv) {
			captured.append(sv);
			segments += 1;
		});

	// The range must actually be non-contiguous, otherwise the test would pass
	// even with the bug present.
	REQUIRE(segments >= 2);
	// Every byte must be captured, in order.
	REQUIRE(captured.size() == pattern.size());
	REQUIRE(captured == pattern);
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

TEST_CASE("Fork before main()", "[Fork]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
extern void _exit(int);
int main() {
	printf("Hello World!\n");
	_exit(666);
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

	tinykvm::Machine machine1 { binary, {
		.max_mem = 10ull << 20, // We need 10mb because of fragmentation
	} };
	machine1.setup_linux({"fork"}, env);
	machine1.prepare_copy_on_write();
	REQUIRE(machine1.is_forkable());
	REQUIRE(!machine1.is_forked());

	tinykvm::Machine machine2 { binary, {
		.max_mem = 10ull << 20,
	} };
	machine2.prepare_copy_on_write(); // No Linux setup
	REQUIRE(machine2.is_forkable());
	REQUIRE(!machine2.is_forked());

	/// -- full resets -- ///

	auto fork1 = tinykvm::Machine { machine1, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork1.run(4.0f);
		REQUIRE(fork1.return_value() == 666);

		fork1.reset_to(machine1, {
			.max_cow_mem = 4ul << 20,
		});
	}

	auto fork2 = tinykvm::Machine { machine2, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork2.setup_linux({"fork"}, env);
		fork2.run(4.0f);
		REQUIRE(fork2.return_value() == 666);

		fork2.reset_to(machine2, {
			.max_cow_mem = 4ul << 20,
		});
	}

	/// -- keep working memory resets -- ///

	auto fork3 = tinykvm::Machine { machine1, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork3.run(4.0f);
		REQUIRE(fork3.return_value() == 666);

		fork3.reset_to(machine1, {
			.max_cow_mem = 4ul << 20,
			.reset_keep_all_work_memory = true
		});
	}

	auto fork4 = tinykvm::Machine { machine2, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork4.setup_linux({"fork"}, env);
		fork4.run(4.0f);
		REQUIRE(fork4.return_value() == 666);

		fork4.reset_to(machine2, {
			.max_cow_mem = 4ul << 20,
			.reset_keep_all_work_memory = true
		});
	}
}

TEST_CASE("Fork before main() 4k edition", "[Fork]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
extern void _exit(int);
int main() {
	printf("Hello World!\n");
	_exit(666);
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

	tinykvm::Machine machine1 { binary, {
		.max_mem = 16ull << 20, // We need 16mb because of fragmentation
		.split_hugepages = true,
		.split_all_hugepages_during_loading = true,
	} };
	machine1.setup_linux({"fork"}, env);
	machine1.prepare_copy_on_write();
	REQUIRE(machine1.is_forkable());
	REQUIRE(!machine1.is_forked());

	tinykvm::Machine machine2 { binary, {
		.max_mem = 16ull << 20,
		.split_hugepages = true,
		.split_all_hugepages_during_loading = true,
	} };
	machine2.prepare_copy_on_write(); // No Linux setup
	REQUIRE(machine2.is_forkable());
	REQUIRE(!machine2.is_forked());

	/// -- full resets -- ///

	auto fork1 = tinykvm::Machine { machine1, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork1.run(4.0f);
		REQUIRE(fork1.return_value() == 666);

		fork1.reset_to(machine1, {
			.max_cow_mem = 4ul << 20,
		});
	}

	auto fork2 = tinykvm::Machine { machine2, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork2.setup_linux({"fork"}, env);
		fork2.run(4.0f);
		REQUIRE(fork2.return_value() == 666);

		fork2.reset_to(machine2, {
			.max_cow_mem = 4ul << 20,
		});
	}

	/// -- keep working memory resets -- ///

	auto fork3 = tinykvm::Machine { machine1, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork3.run(4.0f);
		REQUIRE(fork3.return_value() == 666);

		fork3.reset_to(machine1, {
			.max_cow_mem = 4ul << 20,
			.reset_keep_all_work_memory = true
		});
	}

	auto fork4 = tinykvm::Machine { machine2, {
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	for (int i = 0; i < 100; i++)
	{
		fork4.setup_linux({"fork"}, env);
		fork4.run(4.0f);
		REQUIRE(fork4.return_value() == 666);

		fork4.reset_to(machine2, {
			.max_cow_mem = 4ul << 20,
			.reset_keep_all_work_memory = true
		});
	}
}

/* Regression test for the cross-process master path (fast-agent issue #18,
   fixed on ARM64 by tinykvm#114). --process-per-vm boots one master and
   fork()s a zygote; every worker then constructs its own TinyKVM fork of the
   inherited master from a *different* process than the one that built it.
   KVM binds a VM to the creating process's mm (docs/architecture/
   process-per-vm.md, fact 1): any vCPU ioctl issued against the master's fd
   from another process fails with -EIO. The fork constructor and reset_to()
   must therefore never ioctl `other`'s vcpu fd -- everything they need (GPRs
   and sregs via the synced-regs page, FPU via the prepare-time snapshot) must
   already be readable from userspace state that crossed the fork() boundary.
   This is exactly the property that broke on ARM64 before tinykvm#114:
   setup_cow_mode() read five EL1 sysregs straight off the master's vcpu fd,
   and the constructor's other.registers() could fall back to the same fd
   whenever the register cache was cold -- both fine in-process, both -EIO
   from a worker. The fix snapshots that state into the master at
   prepare_copy_on_write() time, while its fd is still ioctl-able, so the
   worker never has to touch it.

   Masters "stay eager by construction": nothing about consuming a master
   from a different process should depend on state that was lazily faulted in
   and therefore never crossed the process boundary. Mirroring the real
   topology precisely (run() + prepare_copy_on_write() happen once, in the
   single-threaded parent, before the OS-level fork() -- see process-per-vm.md
   fact 4) is what makes this a faithful regression guard rather than a
   synthetic one. */
TEST_CASE("Cross-process master path: a worker builds and runs its own fork", "[Fork]")
{
	const auto binary = build_and_load(R"M(
int main() {
}
static int value = 0;
extern int get_value() {
	value++;
	return value;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"fork"}, env);
	// Everything the fork constructor needs from the master must be settled
	// here, in the single-threaded parent, before the OS-level fork() below.
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	struct WorkerResult {
		bool constructed = false;
		bool ran_ok = false;
		bool reset_ok = false;
		bool ran_again_ok = false;
		long value1 = -1;
		long value2 = -1;
		char error[256] = {0};
	};

	int pipefd[2];
	REQUIRE(pipe(pipefd) == 0);

	fflush(nullptr);
	const pid_t pid = fork();
	REQUIRE(pid >= 0);

	if (pid == 0) {
		/* Worker process: never touches the parent's `machine` object again
		   except through the state that crossed fork() -- no ioctl on the
		   master's vcpu fd is possible here (KVM binds the VM to the
		   creating process's mm), so any regression back to a live read of
		   `other`'s fd fails loudly with -EIO instead of silently. */
		close(pipefd[0]);
		WorkerResult result{};
		try {
			tinykvm::Machine fork_vm { machine, {
				.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
			}};
			result.constructed = true;

			fork_vm.timed_vmcall(get_value, 4.0f);
			result.value1 = fork_vm.return_value();
			result.ran_ok = (result.value1 == 1);

			/* The process-per-vm worker lifecycle recycles across tenants via
			   reset_to() (process-per-vm.md, "Worker lifetime policy") --
			   still cross-process, still must not touch the master's fd. */
			fork_vm.reset_to(machine, {
				.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
			});
			result.reset_ok = true;

			fork_vm.timed_vmcall(get_value, 4.0f);
			result.value2 = fork_vm.return_value();
			result.ran_again_ok = (result.value2 == 1);
		} catch (const std::exception& e) {
			strncpy(result.error, e.what(), sizeof(result.error) - 1);
		}
		[[maybe_unused]] const ssize_t w = write(pipefd[1], &result, sizeof(result));
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	WorkerResult result{};
	const ssize_t r = read(pipefd[0], &result, sizeof(result));
	close(pipefd[0]);

	int status = 0;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);

	REQUIRE(r == (ssize_t) sizeof(result));
	INFO("worker error: " << result.error);
	REQUIRE(result.constructed);
	REQUIRE(result.ran_ok);
	REQUIRE(result.value1 == 1);
	REQUIRE(result.reset_ok);
	REQUIRE(result.ran_again_ok);
	REQUIRE(result.value2 == 1);

	/* The master itself is unharmed: it is still forkable in the parent, and
	   a fresh fork built here (in-process this time) behaves identically. */
	auto fork_in_parent = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	}};
	fork_in_parent.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork_in_parent.return_value() == 1);
}

/* Regression test for the fork-path set_tls_base seat/tid coupling (fast-agent
   issue #20). docs/design/create-fork-vm-pooling.md (the "Correct design"
   section under lever C) calls out threads.cpp:101 -- MultiThreading::reset_to
   -- as a fork-construction call site that performs a read-modify-write of
   the fork's sregs via set_tls_base(). That call only fires when the master's
   *current* thread id differs from the default (1) every fresh
   MultiThreading starts with, so the ordinary single-thread case (master
   never touches threads() at all) never exercises it. This builds a master
   whose current thread id is not 1 before it is snapshotted, then confirms
   the fork's FS base lands correctly -- first via the C++ accessor (the
   userspace synced-regs mirror, correct even before the fork ever runs), and
   again via a raw KVM_GET_SREGS ioctl after running the fork once, so the
   dirty synced-regs bits have actually been consumed into real vCPU state.
   The seat is exercised at the host level via MultiThreading's public API
   (tinykvm/linux/threads.hpp) rather than a fragile guest-side clone()
   dance -- this is a fork-construction/reset invariant, not a scheduler
   behavior, so it does not need real guest threading to expose it. */
TEST_CASE("Fork inherits FS base from master's non-default current thread", "[Fork][Threads]")
{
	const auto binary = build_and_load(R"M(
int main() {
}
extern int get_value() {
	return 42;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"fork"}, env);
	machine.run(4.0f);

	static constexpr uint64_t TLS_MARKER = 0x0000133700001337ULL;
	static constexpr int NON_DEFAULT_TID = 7;

	/* Master's calling thread is not the default tid (1) when it is
	   snapshotted, and its live FS base is the marker below. Setting the
	   Thread record's own cached fsbase (not just the live register) matches
	   what a real activate()/resume() would have left behind, and keeps this
	   test meaningful on both arches (see the ARM64 twin in arm64_fork.cpp,
	   whose reset_to() reads the Thread's cached field directly rather than
	   re-reading a live sreg). */
	auto& thread = machine.threads().create(NON_DEFAULT_TID);
	thread.fsbase = TLS_MARKER;
	machine.threads().set_to_and_suspend_others(NON_DEFAULT_TID);
	machine.set_tls_base(TLS_MARKER);
	REQUIRE(machine.threads().gettid() == NON_DEFAULT_TID);

	machine.prepare_copy_on_write(65536);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	}};

	/* The fork's own thread bookkeeping followed the master's current
	   thread, not the default tid=1 every fresh MultiThreading starts with. */
	REQUIRE(fork.threads().gettid() == NON_DEFAULT_TID);

	/* Correct before the fork has ever run: get_special_registers() reads the
	   mmap'd synced-regs page directly. */
	REQUIRE(fork.get_special_registers().fs.base == TLS_MARKER);

	const auto get_value = fork.address_of("get_value");
	REQUIRE(get_value != 0x0);
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 42);

	/* Strongest possible confirmation: a raw KVM_GET_SREGS ioctl, bypassing
	   every userspace mirror, after KVM has consumed the dirty synced-regs
	   bits into real vCPU state via the run above. */
	struct kvm_sregs sregs {};
	REQUIRE(ioctl(fork.cpu().fd, KVM_GET_SREGS, &sregs) == 0);
	REQUIRE(sregs.fs.base == TLS_MARKER);
}
