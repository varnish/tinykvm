#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <tinykvm/rsp_client.hpp>
#include <elf.h>
#include <limits.h>
#include <stdexcept>
#include <unistd.h>
extern std::vector<uint8_t> load_file(const std::string& filename);
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env{
	"LC_TYPE=C", "LC_ALL=C", "USER=root"};
static const std::vector<uint8_t> ld_linux_x86_64_so
	= load_file("/lib64/ld-linux-x86-64.so.2");

static std::string current_dir_path()
{
	char cwd[PATH_MAX];
	if (getcwd(cwd, sizeof(cwd)) == nullptr) {
		throw std::runtime_error("Failed to resolve current directory");
	}
	return std::string(cwd);
}

static std::string rust_elf_path()
{
	std::string guest_filename = current_dir_path() + "/../unit/elf/rust.elf";
	char abs_path[PATH_MAX];
	realpath(guest_filename.c_str(), abs_path);
	return std::string(abs_path);
}

static Elf64_Shdr* section_by_name_mut(std::vector<uint8_t>& elf, const char* name)
{
	if (elf.size() < sizeof(Elf64_Ehdr)) {
		throw std::runtime_error("ELF too small for header");
	}
	auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(elf.data());
	if (ehdr->e_shoff + ehdr->e_shnum * sizeof(Elf64_Shdr) > elf.size()) {
		throw std::runtime_error("ELF section table outside binary");
	}
	auto* shdr = reinterpret_cast<Elf64_Shdr*>(elf.data() + ehdr->e_shoff);
	if (ehdr->e_shstrndx >= ehdr->e_shnum) {
		throw std::runtime_error("Invalid ELF shstrndx");
	}
	const auto& shstrtab = shdr[ehdr->e_shstrndx];
	if (shstrtab.sh_offset + shstrtab.sh_size > elf.size()) {
		throw std::runtime_error("ELF shstrtab outside binary");
	}
	const char* strings = reinterpret_cast<const char*>(elf.data() + shstrtab.sh_offset);
	for (uint16_t i = 0; i < ehdr->e_shnum; i++)
	{
		const char* shname = strings + shdr[i].sh_name;
		if (strcmp(shname, name) == 0) {
			return &shdr[i];
		}
	}
	return nullptr;
}

static std::vector<uint8_t> make_malformed_relr_size(std::vector<uint8_t> elf)
{
	auto* relr = section_by_name_mut(elf, ".relr.dyn");
	if (relr == nullptr) {
		throw std::runtime_error("ELF is missing .relr.dyn section");
	}
	// Force non-word-sized section length to trigger strict malformed check.
	relr->sh_size += 1;
	return elf;
}

static std::vector<uint8_t> make_malformed_relr_sequence(std::vector<uint8_t> elf)
{
	auto* relr = section_by_name_mut(elf, ".relr.dyn");
	if (relr == nullptr) {
		throw std::runtime_error("ELF is missing .relr.dyn section");
	}
	if (relr->sh_size < sizeof(Elf64_Addr)) {
		throw std::runtime_error("ELF .relr.dyn section is too small");
	}
	if (relr->sh_offset + relr->sh_size > elf.size()) {
		throw std::runtime_error("ELF .relr.dyn payload outside binary");
	}
	auto* relr_entries = reinterpret_cast<Elf64_Addr*>(elf.data() + relr->sh_offset);
	// First entry as bitmap (LSB=1) is invalid because there is no base address yet.
	relr_entries[0] = 1;
	return elf;
}

static std::vector<uint8_t> make_relr_oob_target(std::vector<uint8_t> elf)
{
	auto* relr = section_by_name_mut(elf, ".relr.dyn");
	if (relr == nullptr) {
		throw std::runtime_error("ELF is missing .relr.dyn section");
	}
	if (relr->sh_size < sizeof(Elf64_Addr)) {
		throw std::runtime_error("ELF .relr.dyn section is too small");
	}
	if (relr->sh_offset + relr->sh_size > elf.size()) {
		throw std::runtime_error("ELF .relr.dyn payload outside binary");
	}
	auto* relr_entries = reinterpret_cast<Elf64_Addr*>(elf.data() + relr->sh_offset);
	// Force direct RELR relocation target far beyond guest VM memory range.
	relr_entries[0] = 0x4000000000000000ULL;
	return elf;
}

static std::vector<uint8_t> make_rela_too_many(std::vector<uint8_t> elf)
{
	auto* rela = section_by_name_mut(elf, ".rela.dyn");
	if (rela == nullptr) {
		throw std::runtime_error("ELF is missing .rela.dyn section");
	}
	// Trigger relocate_section guard before payload traversal.
	rela->sh_size = (600001ULL * sizeof(Elf64_Rela));
	return elf;
}

TEST_CASE("Initialize KVM", "[Initialize]")
{
	tinykvm::Machine::init();
}

TEST_CASE("Verify static ELF without dynamic relocation", "[ELF][no-reloc]")
{
	const auto binary = build_and_load(R"M(
int main(int argc, char** argv) {
	(void)argc;
	(void)argv;
	return 123;
}
)M");

	tinykvm::Machine machine{binary, {.max_mem = MAX_MEMORY}};
	machine.setup_linux({"program"}, env);
	machine.run(2.0f);

	REQUIRE(machine.return_value() == 123);
}

TEST_CASE("Verify dynamic Rust ELF relocation support", "[ELF][reloc]")
{
	const std::string guest_filename = rust_elf_path();

	tinykvm::Machine machine { ld_linux_x86_64_so, {
		.max_mem = MAX_MEMORY,
		.verbose_loader = true,
		.executable_heap = true,
		.irelative_mode = tinykvm::MachineOptions::IRelativeMode::BestEffort,
		.mmap_backed_files = true
	} };
	// Allow opening all files (for dynamic linker)
	machine.fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		(void)path;
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

TEST_CASE("Verify dynamic Rust ELF relocation support (himem)", "[ELF][reloc]")
{
	const uint64_t HIMEM = 128ULL << 30; /* 128GB */
	tinykvm::Machine machine{ld_linux_x86_64_so, {
		.max_mem = MAX_MEMORY,
		.dylink_address_hint = HIMEM + 0x200000,
		.vmem_base_address = HIMEM,
		.master_direct_memory_writes = true,
		.executable_heap = true,
		.irelative_mode = tinykvm::MachineOptions::IRelativeMode::BestEffort,
		.mmap_backed_files = true
	}};
	// Use constrained working memory
	machine.prepare_copy_on_write(MAX_MEMORY);
	// Allow opening all files (for dynamic linker)
	machine.fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		(void)path;
		return true;
	});
	// Load the dynamic linker instead of the program
	std::vector<std::string> args;
	args.push_back("/lib64/ld-linux-x86-64.so.2");
	args.push_back(rust_elf_path());
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux(args, env);
	REQUIRE(machine.entry_address() > HIMEM);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 231);
}

TEST_CASE("IRELATIVE strict-fail mode rejects dynamic Rust ELF", "[ELF][reloc]")
{
	const std::string guest_filename = rust_elf_path();

	bool threw = false;
	try {
		tinykvm::Machine machine { ld_linux_x86_64_so, {
			.max_mem = MAX_MEMORY,
			.executable_heap = true,
			.irelative_mode = tinykvm::MachineOptions::IRelativeMode::StrictFail,
			.mmap_backed_files = true,
		} };
		machine.fds().set_open_readable_callback(
		[&] (std::string& path) -> bool {
			(void)path;
			return true;
		});
		std::vector<std::string> args;
		args.push_back("/lib64/ld-linux-x86-64.so.2");
		args.push_back(guest_filename);
		machine.setup_linux(args, env);
		machine.run(4.0f);
	} catch (const tinykvm::MachineException& ex) {
		threw = true;
		REQUIRE(std::string(ex.what()).find("R_X86_64_IRELATIVE") != std::string::npos);
	}

	REQUIRE(threw);
}

TEST_CASE("IRELATIVE default mode is strict-fail", "[ELF][reloc]")
{
	const std::string guest_filename = rust_elf_path();

	bool threw = false;
	try {
		tinykvm::Machine machine { ld_linux_x86_64_so, {
			.max_mem = MAX_MEMORY,
			.executable_heap = true,
			.mmap_backed_files = true,
		} };
		machine.fds().set_open_readable_callback(
		[&] (std::string& path) -> bool {
			(void)path;
			return true;
		});
		std::vector<std::string> args;
		args.push_back("/lib64/ld-linux-x86-64.so.2");
		args.push_back(guest_filename);
		machine.setup_linux(args, env);
		machine.run(4.0f);
	} catch (const tinykvm::MachineException& ex) {
		threw = true;
		REQUIRE(std::string(ex.what()).find("R_X86_64_IRELATIVE") != std::string::npos);
	}

	REQUIRE(threw);
}

TEST_CASE("Malformed RELR section size fails hard", "[ELF][reloc]")
{
	const auto malformed_ld = make_malformed_relr_size(ld_linux_x86_64_so);

	bool threw = false;
	try {
		tinykvm::Machine machine { malformed_ld, {
			.max_mem = MAX_MEMORY,
			.executable_heap = true,
			.irelative_mode = tinykvm::MachineOptions::IRelativeMode::BestEffort,
			.mmap_backed_files = true,
		} };
		(void)machine;
	} catch (const tinykvm::MachineException& ex) {
		threw = true;
		REQUIRE(std::string(ex.what()).find("Malformed RELR section") != std::string::npos);
	}

	REQUIRE(threw);
}

TEST_CASE("Malformed RELR sequence fails hard", "[ELF][reloc]")
{
	const auto malformed_ld = make_malformed_relr_sequence(ld_linux_x86_64_so);

	bool threw = false;
	try {
		tinykvm::Machine machine { malformed_ld, {
			.max_mem = MAX_MEMORY,
			.executable_heap = true,
			.irelative_mode = tinykvm::MachineOptions::IRelativeMode::BestEffort,
			.mmap_backed_files = true,
		} };
		(void)machine;
	} catch (const tinykvm::MachineException& ex) {
		threw = true;
		REQUIRE(std::string(ex.what()).find("Malformed RELR sequence") != std::string::npos);
	}

	REQUIRE(threw);
}

TEST_CASE("RELR out-of-bounds target fails hard", "[ELF][reloc]")
{
	const auto malformed_ld = make_relr_oob_target(ld_linux_x86_64_so);

	bool threw = false;
	try {
		tinykvm::Machine machine { malformed_ld, {
			.max_mem = MAX_MEMORY,
			.executable_heap = true,
			.irelative_mode = tinykvm::MachineOptions::IRelativeMode::BestEffort,
			.mmap_backed_files = true,
		} };
		(void)machine;
	} catch (const tinykvm::MachineException& ex) {
		threw = true;
		REQUIRE(std::string(ex.what()).find("RELR relocation target out of bounds") != std::string::npos);
	}

	REQUIRE(threw);
}

TEST_CASE("RELA excessive relocation count fails hard", "[ELF][reloc]")
{
	const auto malformed_ld = make_rela_too_many(ld_linux_x86_64_so);

	bool threw = false;
	try {
		tinykvm::Machine machine { malformed_ld, {
			.max_mem = MAX_MEMORY,
			.executable_heap = true,
			.irelative_mode = tinykvm::MachineOptions::IRelativeMode::BestEffort,
			.mmap_backed_files = true,
		} };
		(void)machine;
	} catch (const tinykvm::MachineException& ex) {
		threw = true;
		REQUIRE(std::string(ex.what()).find("Too many relocations") != std::string::npos);
	}

	REQUIRE(threw);
}

TEST_CASE("IRELATIVE execute-resolver mode runs dynamic Rust ELF", "[ELF][reloc]")
{
	const std::string guest_filename = rust_elf_path();

	tinykvm::Machine machine { ld_linux_x86_64_so, {
		.max_mem = MAX_MEMORY,
		.executable_heap = true,
		.irelative_mode = tinykvm::MachineOptions::IRelativeMode::ExecuteResolver,
		.mmap_backed_files = true,
	} };
	machine.fds().set_open_readable_callback(
	[&] (std::string& path) -> bool {
		(void)path;
		return true;
	});
	std::vector<std::string> args;
	args.push_back("/lib64/ld-linux-x86-64.so.2");
	args.push_back(guest_filename);
	machine.setup_linux(args, env);
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 231);
}
