#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
extern void setup_kvm_system_calls();

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
	machine.setup_linux(
		{"basic"},
		{"LC_TYPE=C", "LC_ALL=C", "USER=root"});

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
