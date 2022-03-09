#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string& code);
extern void setup_kvm_system_calls();
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
	// Install Linux and POSIX system call handlers
	setup_kvm_system_calls();
}

TEST_CASE("Instantiate machines", "[Instantiate]")
{
	const auto binary = build_and_load(R"M(
int main() {
	return 666;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };

	// The stack is automatically set to under the program area
	// The default program area is at 4MB on Linux
	REQUIRE(machine.stack_address() == 0x400000);
	// The starting address is somewhere in the program area
	REQUIRE(machine.start_address() > 0x400000);
}

TEST_CASE("Runtime setup and execution", "[Output]")
{
	const auto binary = build_and_load(R"M(
#include <string.h>
int main(int argc, char** argv) {
	if (strcmp(argv[0], "are we passing this correctly?") == 0)
		return 666;
	else
		return -1;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"are we passing this correctly?"}, env);
	machine.run(2.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Execution timeout", "[Output]")
{
	const auto binary = build_and_load(R"M(
#include <string.h>
int main() {
	while (1);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"are we passing this correctly?"}, env);
	REQUIRE_THROWS([&] {
		machine.run(1.0f);
	}());
}

TEST_CASE("Catch output from write system call", "[Output]")
{
	bool output_is_hello_world = false;
	const auto binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
	write(1, "Hello World!", 12);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"basic"}, env);

	machine.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		output_is_hello_world = (text == "Hello World!");
	});
	// Run for at most 4 seconds before giving up
	machine.run(4.0f);

	// We require that the write system call forwarded to the printer
	// and the data matched 'Hello World!'.
	REQUIRE(output_is_hello_world);
}
