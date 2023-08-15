#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string&);
extern void setup_kvm_system_calls();
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env{
	"LC_TYPE=C", "LC_ALL=C", "USER=root"};

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
	// Install Linux and POSIX system call handlers
	setup_kvm_system_calls();
}

TEST_CASE("Writes to kernel memory", "[Integrity]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
int main() {
	printf("Main!\n");
	return 666;
}
void kwrite(long* area)
{
	*area = 0x1234;
	__asm__("hlt");
}
void still_works()
{
	printf("Hello World!\n");
})M");

	/* Create and initialize stdout printing */
	tinykvm::Machine machine{binary, {.max_mem = MAX_MEMORY}};
	machine.setup_linux({"tegridy"}, env);
	machine.run(4.0f);

	const auto func = machine.address_of("kwrite");
	REQUIRE(func != 0x0);
	REQUIRE(machine.address_of("still_works") != 0x0);

	bool output_is_hello_world = false;
	machine.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		if (text == "Hello World!\n")
			output_is_hello_world = true;
	});

	machine.timed_vmcall(
		machine.address_of("still_works"), 1.0f);

	REQUIRE(output_is_hello_world);
	output_is_hello_world = false;

	/* Write something at every X bytes */
	for (long addr = 0x0; addr < 0x12000; addr += 0x10)
	{
		try
		{
			machine.timed_vmcall(func, 1.0f, addr);
		}
		catch (const tinykvm::MachineException& me)
		{
			REQUIRE(std::string(me.what()) != "Halt from kernel space");
		}
	}

	machine.timed_vmcall(
		machine.address_of("still_works"), 1.0f);

	REQUIRE(output_is_hello_world);
}

TEST_CASE("Jumps to kernel memory", "[Integrity]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
int main() {
	printf("Main!\n");
	return 666;
}
void still_works()
{
	printf("Hello World!\n");
})M");

	/* Create and initialize stdout printing */
	tinykvm::Machine machine{binary, {.max_mem = MAX_MEMORY}};
	machine.setup_linux({"tegridy"}, env);
	machine.run(4.0f);

	REQUIRE(machine.address_of("still_works") != 0x0);

	bool output_is_hello_world = false;
	machine.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		if (text == "Hello World!\n")
			output_is_hello_world = true;
	});

	machine.timed_vmcall(
		machine.address_of("still_works"), 1.0f);

	REQUIRE(output_is_hello_world);
	output_is_hello_world = false;

	/* Write something at every X bytes */
	for (long addr = 0x0; addr < 0x12000; addr += 0x10)
	{
		try
		{
			machine.timed_vmcall(addr, 1.0f, 0x1234);
		}
		catch (const std::exception& e)
		{
			// "Shutdown! Triple fault?"
		}
	}

	machine.timed_vmcall(
		machine.address_of("still_works"), 1.0f);

	REQUIRE(output_is_hello_world);
}
