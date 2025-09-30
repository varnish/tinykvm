#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <tinykvm/machine.hpp>
extern std::pair<
	std::string,
	std::vector<uint8_t>
> build_and_load(const std::string& code, const std::string& args);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const uint64_t MAX_COWMEM = 1ul << 20; /* 1MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

TEST_CASE("Initialize KVM", "[Remote]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

TEST_CASE("Print from remote VM", "[Remote]")
{
	const auto storage_binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
	return 1234;
}
extern void remote_hello_world() {
	write(1, "Hello Remote World!", 19);
}
)M", "-Wl,-Ttext-segment=0x40400000");

	// Extract storage remote symbols
	const std::string command = "objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* " + storage_binary.first + " storage.syms";
	FILE* f = popen(command.c_str(), "r");
	if (f == nullptr) {
		throw std::runtime_error("Unable to extract remote symbols");
	}
	pclose(f);

	const auto main_binary = build_and_load(R"M(
extern void remote_hello_world();
int main() {
	remote_hello_world();
	return 2345;
}
)M", "-Wl,--just-symbols=storage.syms");

	tinykvm::Machine storage { storage_binary.second, {
		.max_mem = 16ULL << 20, // MB
		.vmem_base_address = 1ULL << 30, // 1GB
	} };
	storage.setup_linux({"storage"}, env);
	storage.run(4.0f);
	REQUIRE(storage.return_value() == 1234);

	tinykvm::Machine machine { main_binary.second, {
		.max_mem = MAX_MEMORY
	} };
	machine.setup_linux({"main"}, env);
	machine.remote_connect(storage);
	machine.set_remote_allow_page_faults(true);
	REQUIRE(machine.has_remote());

	bool output_is_hello_world = false;
	storage.set_printer([&] (const char* data, size_t size) {
		std::string_view text{data, size};
		output_is_hello_world = (text == "Hello Remote World!");
		REQUIRE(machine.is_remote_connected());
	});

	machine.run(4.0f);
	REQUIRE(machine.return_value() == 2345);
	REQUIRE(output_is_hello_world);
	REQUIRE(!machine.is_remote_connected());
	REQUIRE(machine.remote_connection_count() == 1);
}

TEST_CASE("Fail accessing remote VM directly", "[Remote]")
{
	const auto storage_binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
int main() {
	return 1234;
}
int remote_integer = 0;
extern void remote_integer_set() {
	remote_integer = 42;
}
extern int* remote_integer_get() {
	return &remote_integer;
}
extern void remote_array_write(char* cp, unsigned len) {
	for (unsigned i = 0; i < len; i++) {
		cp[i] = (char)(i & 0xFF);
	}
}
)M", "-Wl,-Ttext-segment=0x40400000");

	// Extract storage remote symbols
	const std::string command = "objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* " + storage_binary.first + " storage.syms";
	FILE* f = popen(command.c_str(), "r");
	if (f == nullptr) {
		throw std::runtime_error("Unable to extract remote symbols");
	}
	pclose(f);

	const auto main_binary = build_and_load(R"M(
extern int* remote_integer_get();
extern void remote_integer_set();
extern void remote_array_write(char*, unsigned);
int main() {
	remote_integer_set();
	int* p = remote_integer_get();
	if ((long)p > 0x40400000 && (long)p < 0x40A00000) {
		return 2345;
	}
	return 0;
}
extern void test_failing() {
	int* p = remote_integer_get();
	*p = 123; // This should cause a fault
}
extern int test_remote_array()
{
	char arr[65536];
	remote_array_write(arr, sizeof(arr));
	for (int i = 0; i < sizeof(arr); i++) {
		// We should be able to read this
		if (arr[i] != (char)(i & 0xFF)) {
			// Failed
			return 1;
		}
		// and write to it
		arr[i] = 0;
	}
	return 0;
}
)M", "-Wl,--just-symbols=storage.syms");

	tinykvm::Machine storage { storage_binary.second, {
		.max_mem = 16ULL << 20, // MB
		.vmem_base_address = 1ULL << 30, // 1GB
	} };
	storage.setup_linux({"storage"}, env);
	storage.run(4.0f);
	REQUIRE(storage.return_value() == 1234);

	tinykvm::Machine machine { main_binary.second, {
		.max_mem = MAX_MEMORY
	} };
	machine.setup_linux({"main"}, env);
	machine.remote_connect(storage);
	machine.set_remote_allow_page_faults(true);
	REQUIRE(machine.has_remote());

	machine.run(4.0f);
	REQUIRE(machine.return_value() == 2345);
	REQUIRE(!machine.is_remote_connected());
	REQUIRE(machine.remote_connection_count() == 2);

	REQUIRE_THROWS([&machine]() {
		machine.vmcall("test_failing");
	}());

	// Create a fork
	machine.prepare_copy_on_write(1UL << 20);
	tinykvm::Machine fork(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	});
	fork.set_remote_allow_page_faults(true);

	REQUIRE_THROWS([&fork]() {
		fork.vmcall("test_failing");
	}());

	fork.vmcall("test_remote_array");
	REQUIRE(fork.return_value() == 0);
}

TEST_CASE("Permanent (reverse) remote function calls", "[Remote]")
{
	const auto storage_binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
#include <stdio.h>
int remote_integer = 0;
int main() {
	printf("Remote integer address: %p\n", &remote_integer);
	return 1234;
}
extern void remote_integer_set() {
	remote_integer = 42;
}
extern int* remote_integer_ptr() {
	return &remote_integer;
}
extern int remote_integer_get() {
	return remote_integer;
}
extern void remote_array_write(char* cp, unsigned len) {
	for (unsigned i = 0; i < len; i++) {
		cp[i] = (char)(i & 0xFF);
	}
}
)M", "-Wl,-Ttext-segment=0x40400000");

	// Extract storage remote symbols
	const std::string command = "objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* " + storage_binary.first + " storage.syms";
	FILE* f = popen(command.c_str(), "r");
	if (f == nullptr) {
		throw std::runtime_error("Unable to extract remote symbols");
	}
	pclose(f);

	const auto main_binary = build_and_load(R"M(
#include <stdio.h>
extern int* remote_integer_ptr();
extern int remote_integer_get();
extern void remote_integer_set();
extern void remote_array_write(char*, unsigned);
int main() {
	remote_integer_set();
	int* p = remote_integer_ptr();
	if ((long)p > 0x40400000 && (long)p < 0x40A00000) {
		return 2345;
	}
	return (long)p;
}
extern void test_failing() {
	int* p = remote_integer_ptr();
	*p = 123; // This should cause a fault
}
extern int test_remote_array()
{
	char arr[65536];
	printf("Testing remote array write arr=%p\n", (void*)arr);
	fflush(stdout);
	remote_array_write(arr, sizeof(arr));
	for (int i = 0; i < sizeof(arr); i++) {
		// We should be able to read this
		if (arr[i] != (char)(i & 0xFF)) {
			// Failed
			return 1;
		}
		// and write to it
		arr[i] = 0;
	}
	return 0;
}
extern int test_many_calls()
{
	int sum = 0;
	for (int i = 0; i < 1000; i++) {
		int p = remote_integer_get();
		sum += p;
	}
	return sum;
}
)M", "-Wl,--just-symbols=storage.syms");

	tinykvm::Machine storage { storage_binary.second, {
		.max_mem = 16ULL << 20, // MB
		.vmem_base_address = 1ULL << 30, // 1GB
	} };
	storage.setup_linux({"storage"}, env);
	storage.run(4.0f);
	REQUIRE(storage.return_value() == 1234);

	tinykvm::Machine machine { main_binary.second, {
		.max_mem = MAX_MEMORY
	} };
	machine.setup_linux({"main"}, env);
	machine.set_remote_allow_page_faults(true);

	machine.permanent_remote_connect(storage);
	REQUIRE(machine.has_remote());

	machine.run(4.0f);
	REQUIRE(machine.return_value() == 2345);
	REQUIRE(!machine.is_remote_connected());
	REQUIRE(machine.remote_connection_count() == 2);

	REQUIRE_THROWS([&machine]() {
		machine.vmcall("test_failing");
	}());

	// Create a fork *without* permanent remote connection
	machine.prepare_copy_on_write(1024*1024);
	tinykvm::Machine fork(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	});
	fork.set_remote_allow_page_faults(true);
	REQUIRE(fork.has_remote());

	REQUIRE_THROWS([&fork]() {
		fork.vmcall("test_failing");
	}());

	fork.vmcall("test_remote_array");
	REQUIRE(fork.return_value() == 0);

	// Create a fork *with* permanent remote connection
	tinykvm::Machine fork2(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	});
	fork2.set_remote_allow_page_faults(true);
	fork2.permanent_remote_connect(storage);
	REQUIRE(fork2.has_remote());

	REQUIRE_THROWS([&fork2]() {
		fork2.vmcall("test_failing");
	}());

	fork2.vmcall("test_many_calls");
	REQUIRE(fork2.return_value() == 42000);
}

TEST_CASE("Remote resume", "[Remote]")
{
	const auto storage_binary = build_and_load(R"M(
extern long write(int, const void*, unsigned long);
#include <stdio.h>
#include <string.h>
__asm__(".global storage_wait_paused\n"
	".type storage_wait_paused, @function\n"
	"storage_wait_paused:\n"
	".cfi_startproc\n"
	"	mov $0x10002, %eax\n"
	"	out %eax, $0\n"
	"   wrfsbase %rdi\n"
	"	ret\n"
	".cfi_endproc\n");
extern size_t storage_wait_paused(void** ptr);

int main() {
	while (1) {
		void* p = NULL;
		size_t len = storage_wait_paused(&p);
		memset(p, 0, len);
		strcpy((char*)p, "Data from storage");
	}
	return 1234;
}
)M", "-Wl,-Ttext-segment=0x40400000");

	// Extract storage remote symbols
	const std::string command = "objcopy -w --extract-symbol --strip-symbol=!remote* --strip-symbol=* " + storage_binary.first + " storage.syms";
	FILE* f = popen(command.c_str(), "r");
	if (f == nullptr) {
		throw std::runtime_error("Unable to extract remote symbols");
	}
	pclose(f);

	const auto main_binary = build_and_load(R"M(
#include <stdio.h>
#include <string.h>
__asm__(".global remote_resume\n"
	".type remote_resume, @function\n"
	"remote_resume:\n"
	"	mov $0x10001, %eax\n"
	"	out %eax, $0\n"
	"   ret\n");
extern long remote_resume(void* data, size_t len);
long test_remote() {
	for (int i = 0; i < 100; i++) {
		char buffer[8192];
		remote_resume(buffer, 8192);
		if (strcmp(buffer, "Data from storage") == 0) {
			continue;
		}
		return 1;
	}
	return 2345;
}
int main() {
	return test_remote();
}
)M", "-Wl,--just-symbols=storage.syms");

	static bool is_waiting = false;
	tinykvm::Machine::install_unhandled_syscall_handler(
	[] (tinykvm::vCPU& cpu, unsigned syscall_number) {
		switch (syscall_number) {
		case 0x10001: { // remote_resume
			// Remember buffer address and length values
			const uint64_t src = cpu.registers().rdi;
			const uint64_t len = cpu.registers().rsi;

			cpu.machine().ipre_remote_resume_now(false,
			[src, len] (tinykvm::Machine& m) {
				m.copy_to_guest(m.registers().rdi, &src, sizeof(src));
				m.registers().rax = len;
			});
			return;
		}
		case 0x10002: // wait_for_storage_task_paused
			cpu.stop();
			is_waiting = true;
			return;
		}
		throw std::runtime_error("Unhandled syscall in remote resume test: " + std::to_string(syscall_number));
	});
	tinykvm::Machine storage { storage_binary.second, {
		.max_mem = 16ULL << 20, // MB
		.vmem_base_address = 1ULL << 30, // 1GB
	} };
	storage.setup_linux({"storage"}, env);
	storage.run(4.0f);
	storage.registers().rip += 2; // Skip OUT instruction
	REQUIRE(is_waiting);

	tinykvm::Machine machine { main_binary.second, {
		.max_mem = MAX_MEMORY
	} };
	machine.setup_linux({"main"}, env);

	machine.remote_connect(storage);
	REQUIRE(machine.has_remote());

	machine.run(4.0f);
	REQUIRE(machine.return_value() == 2345);
	REQUIRE(!machine.is_remote_connected());
	REQUIRE(machine.remote_connection_count() == 100);

	// Create a fork
	machine.prepare_copy_on_write();
	tinykvm::Machine fork(machine, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	});
	REQUIRE(fork.has_remote());

	// Test remote resume
	for (int i = 0; i < 100; i++) {
		is_waiting = false;
		fork.vmcall("test_remote");
		REQUIRE(fork.return_value() == 2345);
		REQUIRE(!fork.is_remote_connected());
		REQUIRE(fork.remote_connection_count() == (i + 1) * 100);
		REQUIRE(is_waiting);
	}

	// Test remote resume against a forked storage VM
	storage.prepare_copy_on_write();
	tinykvm::Machine storage_fork(storage, {
		.max_mem = 16ULL << 20, // MB
		.max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	});
	fork.remote_connect(storage_fork);

	// Test remote resume against the forked storage VM
	printf("Testing remote resume against forked storage VM\n");
	for (int i = 0; i < 100; i++) {
		is_waiting = false;
		fork.vmcall("test_remote");
		REQUIRE(fork.return_value() == 2345);
		REQUIRE(!fork.is_remote_connected());
		REQUIRE(fork.remote_connection_count() == 10000 + (i + 1) * 100);
		REQUIRE(is_waiting);
	}
}
