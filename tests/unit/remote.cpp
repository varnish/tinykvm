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
		.mmap_backed_files = false,
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
