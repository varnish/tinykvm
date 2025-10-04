#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> load_file(const std::string& filename);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env{
    "LC_TYPE=C", "LC_ALL=C", "USER=root"};

TEST_CASE("Initialize KVM", "[Initialize]")
{
    // Create KVM file descriptors etc.
    tinykvm::Machine::init();
}

TEST_CASE("Verify Rust ELF", "[ELF]")
{
	const auto binary = load_file("../unit/elf/rust.elf");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	// We need to create a Linux environment for runtimes to work well
	machine.setup_linux({"verify"}, env);

	// Run for at most 4 seconds before giving up
	machine.run(4.0f);

	REQUIRE(machine.return_value() == 231);
}

TEST_CASE("Verify Rust ELF (himem)", "[ELF]")
{
    const auto binary = load_file("../unit/elf/rust.elf");

    const uint64_t HIMEM = 128ULL << 30; /* 128GB */
    tinykvm::Machine machine{binary, {
        .max_mem = MAX_MEMORY,
        .dylink_address_hint = HIMEM + 0x200000,
        .vmem_base_address = HIMEM
    }};
    // We need to create a Linux environment for runtimes to work well
    machine.setup_linux({"verify"}, env);
    REQUIRE(machine.entry_address() > HIMEM);

    // Run for at most 4 seconds before giving up
    machine.run(4.0f);

    REQUIRE(machine.return_value() == 231);
}
