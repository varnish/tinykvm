#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/rsp_client.hpp>
extern std::vector<uint8_t> load_file(const std::string& filename);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env{
	"LC_TYPE=C", "LC_ALL=C", "USER=root"};
static const std::vector<uint8_t> ld_linux_x86_64_so
	= load_file("/lib64/ld-linux-x86-64.so.2");

TEST_CASE("Initialize KVM", "[Initialize]")
{
	tinykvm::Machine::init();
}

TEST_CASE("Verify dynamic Rust ELF", "[ELF]")
{
	std::string guest_filename
		= std::string(get_current_dir_name()) + "/../unit/elf/rust.elf";
	// Make filename absolute
	char abs_path[PATH_MAX];
	realpath(guest_filename.c_str(), abs_path);
	guest_filename = abs_path;

	tinykvm::Machine machine { ld_linux_x86_64_so, {
		.max_mem = MAX_MEMORY,
		.verbose_loader = true,
		.executable_heap = true,
		.mmap_backed_files = true
	} };
	// Allow opening all files (for dynamic linker)
	machine.fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		return true;
	});
	// Load the dynamic linker instead of the program
	std::vector<std::string> args;
	args.push_back("/lib64/ld-linux-x86-64.so.2");
	args.push_back(guest_filename);
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux_system_calls();
	machine.setup_linux(args, env);

	try {
		// Run for at most 4 seconds before giving up
		machine.run(4.0f);
	} catch (const std::exception& ex) {
		printf("Exception: %s\n", ex.what());
		if (getenv("GDB") != nullptr)
		{
			tinykvm::RSP server(guest_filename, machine, 2159);
			printf("Waiting 60s for remote GDB on port 2159...\n");
			auto client = server.accept(60);
			if (client) {
				printf("Now debugging rust.elf\n");
				while(client->process_one());
			}
		}
	}

	REQUIRE(machine.return_value() == 231);
}

TEST_CASE("Verify dynamic Rust ELF (himem)", "[ELF]")
{
	const uint64_t HIMEM = 128ULL << 30; /* 128GB */
	tinykvm::Machine machine{ld_linux_x86_64_so, {
		.max_mem = MAX_MEMORY,
		.dylink_address_hint = HIMEM + 0x200000,
		.vmem_base_address = HIMEM,
		.master_direct_memory_writes = true,
		.executable_heap = true,
		.mmap_backed_files = true
	}};
	// Use constrained working memory
	machine.prepare_copy_on_write(MAX_MEMORY);
	// Allow opening all files (for dynamic linker)
	machine.fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		return true;
	});
	// Load the dynamic linker instead of the program
	std::vector<std::string> args;
	args.push_back("/lib64/ld-linux-x86-64.so.2");
	args.push_back(std::string(get_current_dir_name()) + "/../unit/elf/rust.elf");
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux(args, env);
	REQUIRE(machine.entry_address() > HIMEM);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 231);
}
