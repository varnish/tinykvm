#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string& code);
extern void setup_kvm_system_calls();
static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const uint64_t MAX_COWMEM =  8ul << 20; /* 8MB */
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

TEST_CASE("Execute function in reset VM", "[Reset]")
{
	const auto binary = build_and_load(R"M(
static int a = 0;
static int b = 1;
int main() {
}
extern long get_a() {
	int ta = a;
	a = 333;
	return ta;
}
extern long get_b() {
	int tb = b;
	b = 666;
	return tb;
}
extern long get_mmap(int *z) {
	int total = z[100] + z[200] + z[300] + z[400];
	z[100] = 22;
	z[200] = 44;
	z[300] = 66;
	z[400] = 88;
	return total;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"reset"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	// Make machine forkable (no working memory)
	machine.prepare_copy_on_write(0);

	auto maddr = machine.mmap_allocate(0x1000);

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	for (size_t i = 0; i < 15; i++)
	{
		auto& m = fork;
		m.timed_vmcall(m.address_of("get_a"), 2.0f);
		REQUIRE(m.return_value() == 0);

		m.timed_vmcall(m.address_of("get_b"), 2.0f);
		REQUIRE(m.return_value() == 1);

		m.timed_vmcall(m.address_of("get_mmap"), 2.0f, (uint64_t)maddr);
		REQUIRE(m.return_value() == 0);

		m.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});
	}
}

TEST_CASE("Execute function in VM (crash recovery)", "[Reset]")
{
	const auto binary = build_and_load(R"M(
#include <assert.h>
#include <stdio.h>
int main() {
	printf("Main!\n");
}

__asm__(".global some_syscall\n"
	".type some_syscall, @function\n"
	"some_syscall:\n"
	".cfi_startproc\n"
	"	mov $0x10000, %eax\n"
	"	out %eax, $0\n"
	"	ret\n"
	".cfi_endproc\n");
extern long some_syscall();

extern long hello_world(const char *arg) {
	printf("%s\n", arg);
	return some_syscall();
}
extern void crash(const char *arg) {
	some_syscall();
	printf("%s\n", arg);
	some_syscall();
	assert(0);
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"reset"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);
	// Make machine forkable (no working memory)
	machine.prepare_copy_on_write(0);

	// Create fork
	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };

	tinykvm::Machine::install_unhandled_syscall_handler(
	[] (tinykvm::vCPU& cpu, unsigned scall) {
		auto regs = cpu.registers();
		switch (scall) {
			case 0x10000: // Some function
				regs.rax = 1023;
				break;
			default:
				regs.rax = -ENOSYS;
		}
		cpu.set_registers(regs);
	});

	bool output_is_hello_world = false;
	fork.set_printer([&] (const char* data, size_t size) {
		std::string text{data, data + size};
		if (text == "Hello World!\n")
			output_is_hello_world = true;
	});

	// Print and crash, verify recovery after reset
	for (size_t i = 0; i < 15; i++)
	{
		auto& m = fork;

		output_is_hello_world = false;
		m.timed_vmcall(m.address_of("hello_world"), 2.0f, "Hello World!");
		REQUIRE(m.return_value() == 1023);
		REQUIRE(output_is_hello_world);

		output_is_hello_world = false;
		m.timed_vmcall(m.address_of("hello_world"), 2.0f, "Hello World!");
		REQUIRE(m.return_value() == 1023);
		REQUIRE(output_is_hello_world);

		output_is_hello_world = false;
		try {
			m.timed_vmcall(m.address_of("crash"), 2.0f, "Hello World!");
		} catch (...) {}
		REQUIRE(output_is_hello_world);

		m.reset_to(machine, {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = MAX_COWMEM
		});
	}
}
