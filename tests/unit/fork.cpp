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
	machine.setup_linux({"basic"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);

	// write syscall not called yet
	REQUIRE(!output_is_hello_world);

	// Make machine forkable
	machine.prepare_copy_on_write();
	REQUIRE(machine.is_forkable());
	REQUIRE(!machine.is_forked());

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_MEMORY
	} };
	fork.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		output_is_hello_world = (text == "Hello World!");
	});

	// write syscall not called yet
	REQUIRE(!output_is_hello_world);

	auto funcaddr = fork.address_of("prints_hello_world");
	fork.timed_vmcall(funcaddr, 4.0f);

	// Now the output should be written out
	REQUIRE(output_is_hello_world);
}
