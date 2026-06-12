#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>
#include <tinykvm/machine.hpp>

extern std::vector<uint8_t> build_and_load(const std::string& code);
extern std::pair<std::string, std::vector<uint8_t>>
	build_and_load_dynamic(const std::string& code, const std::string& args);
extern std::vector<uint8_t> load_file(const std::string& filename);
static const uint64_t MAX_MEMORY = 16ul << 20; /* 16MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};
static const char* LD_LINUX = "/lib/ld-linux-aarch64.so.1";

// The Machine only keeps a view of the binary, so the bytes must outlive it.
static const std::vector<uint8_t>& ld_linux_binary()
{
	static const std::vector<uint8_t> binary = load_file(LD_LINUX);
	return binary;
}

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

TEST_CASE("ARM64 instantiates a static ELF", "[arm64][elf]")
{
	require_arm64_kvm();
	const auto binary = build_and_load(R"M(
int main() {
	return 666;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };

	REQUIRE(machine.start_address() > 0x400000);
	REQUIRE(machine.stack_address() > machine.start_address());
}

TEST_CASE("ARM64 runs a static ELF to completion", "[arm64][elf]")
{
	require_arm64_kvm();
	const auto binary = build_and_load(R"M(
#include <string.h>
int main(int argc, char** argv) {
	(void)argc;
	if (strcmp(argv[0], "are we passing this correctly?") == 0)
		return 666;
	else
		return -1;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"are we passing this correctly?"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 ELF write system call reaches the printer", "[arm64][elf]")
{
	require_arm64_kvm();
	bool output_is_hello_world = false;
	const auto binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
	write(1, "Hello World!", 12);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"hello"}, env);
	machine.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		output_is_hello_world = (text == "Hello World!");
	});
	machine.run(4.0f);

	REQUIRE(output_is_hello_world);
}

TEST_CASE("ARM64 ELF heap allocation and string routines", "[arm64][elf]")
{
	require_arm64_kvm();
	// memset/memcpy exercise the EL0 dc zva and ctr_el0 paths in glibc.
	const auto binary = build_and_load(R"M(
#include <stdlib.h>
#include <string.h>
int main() {
	const unsigned size = 256 * 1024;
	char* a = malloc(size);
	char* b = malloc(size);
	if (!a || !b) return -1;
	memset(a, 0x5A, size);
	memcpy(b, a, size);
	int sum = 0;
	for (unsigned i = 0; i < size; i += 4096)
		sum += b[i];
	free(a);
	free(b);
	return sum == 0x5A * (int)(size / 4096) ? 666 : -1;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"heap"}, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 vmcall into an ELF function", "[arm64][elf]")
{
	require_arm64_kvm();
	const auto binary = build_and_load(R"M(
__attribute__((noinline, used))
long bump(long x) {
	return x + 21;
}
int main() {
	return 0;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"vmcall"}, env);
	machine.run(4.0f);
	REQUIRE(machine.return_value() == 0);

	machine.vmcall("bump", 21);
	REQUIRE(machine.return_value() == 42);
}

TEST_CASE("ARM64 forked ELF vmcalls are isolated by CoW", "[arm64][elf]")
{
	require_arm64_kvm();
	const tinykvm::MachineOptions options {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = 4ul << 20,
		.split_hugepages = true,
	};
	const auto binary = build_and_load(R"M(
static long counter = 1000;
__attribute__((noinline, used))
long increment(long x) {
	counter += x;
	return counter;
}
int main() {
	return 0;
})M");

	tinykvm::Machine master { binary, options };
	master.setup_linux({"fork"}, env);
	master.run(4.0f);
	master.prepare_copy_on_write(options.max_cow_mem);

	tinykvm::Machine fork { master, options };
	fork.vmcall("increment", 5);
	REQUIRE(fork.return_value() == 1005);
	fork.vmcall("increment", 5);
	REQUIRE(fork.return_value() == 1010);

	// The fork's writes must not leak into the master: a reset fork
	// starts from the master's value again.
	fork.reset_to(master, options);
	fork.vmcall("increment", 7);
	REQUIRE(fork.return_value() == 1007);
}

TEST_CASE("ARM64 runs a dynamic ELF via the interpreter", "[arm64][elf]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load_dynamic(R"M(
#include <string.h>
int main(int argc, char** argv) {
	(void)argc;
	if (strcmp(argv[1], "dynamic!") == 0)
		return 666;
	else
		return -1;
})M", "-fPIE -pie");

	// Load the dynamic linker as the program, with the real program
	// as its first argument — the same scheme the amd64 ELF tests use.
	tinykvm::Machine machine { ld_linux_binary(), {
		.max_mem = 64ul << 20,
	} };
	// Allow the dynamic linker to open the program and its libraries
	machine.fds().set_open_readable_callback(
		[] (std::string&) -> bool { return true; });
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_mmap_syscalls(true);
	}
	machine.setup_linux({LD_LINUX, program, "dynamic!"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 dynamic ELF stdio and heap work", "[arm64][elf]")
{
	require_arm64_kvm();
	const auto [program, binary] = build_and_load_dynamic(R"M(
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main() {
	char* buf = malloc(64);
	if (!buf) return -1;
	snprintf(buf, 64, "Hello %s World!", "Dynamic");
	fputs(buf, stdout);
	fflush(stdout);
	free(buf);
	return 666;
})M", "-no-pie");

	bool output_matches = false;
	// A non-PIE dynamic executable must be mapped at its fixed link
	// address (0x400000 here); move the heap/stack/mmap arena above it.
	tinykvm::Machine machine { ld_linux_binary(), {
		.max_mem = 64ul << 20,
		.heap_address_hint = 16ul << 20,
	} };
	machine.fds().set_open_readable_callback(
		[] (std::string&) -> bool { return true; });
	machine.setup_linux({LD_LINUX, program}, env);
	machine.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		output_matches = (text == "Hello Dynamic World!");
	});
	machine.run(8.0f);

	REQUIRE(output_matches);
	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ARM64 runs a dynamic Python guest", "[arm64][elf]")
{
	require_arm64_kvm();
	if (access("/usr/bin/python3", R_OK) != 0) {
		SKIP("python3 not available on this host");
	}

	std::string output;
	// libpython3.13 is >4MB, so with mmap_backed_files its mmap is served
	// by a host-mmap'd file-backed memory region instead of preadv.
	tinykvm::Machine machine { ld_linux_binary(), {
		.max_mem = 512ul << 20,
		.mmap_backed_files = true,
	} };
	machine.fds().set_open_readable_callback(
		[] (std::string&) -> bool { return true; });
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_mmap_syscalls(true);
	}
	machine.setup_linux({LD_LINUX, "/usr/bin/python3", "-c",
		"print('Hello Python World!')"}, env);
	machine.set_printer([&] (const char* data, size_t size) {
		output.append(data, size);
	});
	machine.run(16.0f);

	REQUIRE(output == "Hello Python World!\n");
	REQUIRE(machine.return_value() == 0);
	// libpython must have been served by a file-backed memory region,
	// not the preadv fallback.
	REQUIRE(!machine.main_memory().mmap_ranges.empty());
}
