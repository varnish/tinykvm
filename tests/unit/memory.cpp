#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <elf.h>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */

TEST_CASE("Initialize KVM", "[Memory]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

TEST_CASE("Memory range checks", "[Memory]")
{
	const auto binary = build_and_load(R"M(
int main() {
	return 666;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	const auto& mem = machine.main_memory();
	const uint64_t endbase = mem.physbase + mem.size;

	/* Ordinary ranges inside the safe area */
	REQUIRE(mem.safely_within(mem.safebase, 8));
	REQUIRE(mem.safely_within(mem.safebase, endbase - mem.safebase));
	REQUIRE(mem.safely_within(endbase - 8, 8));
	REQUIRE(mem.within(mem.physbase, 8));

	/* Below the safe base, and past the end */
	REQUIRE(!mem.safely_within(mem.safebase - 1, 8));
	REQUIRE(!mem.safely_within(0x0, 8));
	REQUIRE(!mem.safely_within(endbase - 8, 9));
	REQUIRE(!mem.safely_within(endbase, 8));
}

TEST_CASE("Memory range checks do not overflow", "[Memory]")
{
	const auto binary = build_and_load(R"M(
int main() {
	return 666;
})M");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	const auto& mem = machine.main_memory();
	const uint64_t endbase = mem.physbase + mem.size;

	/* A valid base with a length that wraps around must not appear
	   to end inside memory. */
	REQUIRE(!mem.safely_within(mem.safebase, UINT64_MAX));
	REQUIRE(!mem.safely_within(mem.safebase, ~mem.safebase + 1)); /* addr + size == 0 */
	REQUIRE(!mem.safely_within(endbase - 8, UINT64_MAX));

	/* A wildly out-of-range base whose length wraps back into memory.
	   Both of these end up "inside" memory without the overflow check. */
	REQUIRE(!mem.safely_within(UINT64_MAX, 1));
	REQUIRE(!mem.safely_within(UINT64_MAX - 8, 16));
	REQUIRE(!mem.safely_within(UINT64_MAX, mem.safebase + 9));

	/* The unsafe variant has the same guarantee */
	REQUIRE(!mem.within(mem.physbase, UINT64_MAX));
	REQUIRE(!mem.within(UINT64_MAX, mem.physbase + 9));

	/* And the checks the rest of the library actually calls */
	REQUIRE(!machine.memory_safe_at(mem.safebase, UINT64_MAX));
	REQUIRE(!machine.memory_safe_at(UINT64_MAX - 8, 16));
	REQUIRE_THROWS_AS(machine.memory_at(mem.safebase, UINT64_MAX),
		tinykvm::MemoryException);
	REQUIRE_THROWS_AS(machine.memory_at(UINT64_MAX - 8, 16),
		tinykvm::MemoryException);
}

TEST_CASE("Overflowing ELF segments are rejected", "[Memory]")
{
	auto binary = build_and_load(R"M(
int main() {
	return 666;
})M");

	/* Give the first PT_LOAD segment a length that wraps around when
	   added to its virtual address. The loader guards this before it
	   reaches the safely_within() bounds check, and must keep doing so. */
	auto* ehdr = (Elf64_Ehdr *)binary.data();
	auto* phdr = (Elf64_Phdr *)&binary.at(ehdr->e_phoff);
	bool patched = false;
	for (unsigned i = 0; i < ehdr->e_phnum; i++) {
		if (phdr[i].p_type == PT_LOAD) {
			phdr[i].p_memsz = UINT64_MAX - phdr[i].p_vaddr + 1;
			phdr[i].p_filesz = 0x1000;
			patched = true;
			break;
		}
	}
	REQUIRE(patched);

	REQUIRE_THROWS([&] {
		tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	}());
}
