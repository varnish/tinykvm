#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
extern std::vector<uint8_t> build_and_load(const std::string &code);
static const uint64_t MAX_MEMORY = 8ul << 20; /* 8MB */
static const std::vector<std::string> env{
	"LC_TYPE=C", "LC_ALL=C", "USER=root"};

TEST_CASE("Initialize KVM", "[Initialize]")
{
	// Create KVM file descriptors etc.
	tinykvm::Machine::init();
}

TEST_CASE("Basic mmap and munmap", "[MMAP]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
#include <sys/mman.h>
int main(int argc, char** argv) {
	return 666;
}
void* do_mmap(size_t size) {
	void *res = mmap(NULL, size, 0x7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	//printf("mmap(%zu) = %p\n", size, res);
	//fflush(stdout);
	return res;
}
int do_munmap(void* addr, size_t size) {
	int res = munmap(addr, size);
	//printf("munmap(%p, %zu) = %d\n", addr, size, res);
	//fflush(stdout);
	return res;
}
)M");

	tinykvm::Machine machine{binary, {.max_mem = MAX_MEMORY}};
	machine.setup_linux({"program"}, env);
	//machine.set_verbose_system_calls(true);
	machine.run(2.0f);
	REQUIRE(machine.return_value() == 666);

	for (int i = 0; i < 10; ++i)
	{
		// Make a single mmap call
		machine.vmcall("do_mmap", 0x1000000);
		const uint64_t guest_mmap_addr = machine.return_value();
		REQUIRE(guest_mmap_addr >= machine.mmap_start());
		REQUIRE(guest_mmap_addr != ~0UL);
		REQUIRE((guest_mmap_addr & 0xFFF) == 0);
		// Since this is a single page, we can use writable_memview
		// on a page (which must be sequential in memory)
		auto mmap_page = machine.writable_memview(guest_mmap_addr, 0x1000);
		REQUIRE(!mmap_page.empty());
		// We can memset the entire page
		std::memset(mmap_page.data(), 0xFF, mmap_page.size());

		// Unmapping and then mapping again should return the same address
		machine.vmcall("do_munmap", guest_mmap_addr, 0x1000000);
		REQUIRE(machine.return_value() == 0);

		machine.vmcall("do_mmap", 0x1000000);
		const uint64_t new_guest_mmap_addr = machine.return_value();
		REQUIRE(new_guest_mmap_addr == guest_mmap_addr);
		// Check that the address is still valid
		auto mmap_page_after_unmap = machine.writable_memview(new_guest_mmap_addr, 0x1000);
		REQUIRE(!mmap_page_after_unmap.empty());

		// Unmap the page
		machine.vmcall("do_munmap", new_guest_mmap_addr, 0x1000000);
	}
}

TEST_CASE("Randomize mappings avoiding collisions", "[MMAP]")
{
	const auto binary = build_and_load(R"M(
#include <stdio.h>
#include <sys/mman.h>
int main(int argc, char** argv) {
	return 666;
}
void* do_mmap(size_t size) {
	void *res = mmap(NULL, size, 0x7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	return res;
}
void* do_fixed_mmap(void* m, size_t size) {
	void *res = mmap(m, size, 0x7, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	return res;
}
int do_munmap(void* addr, size_t size) {
	int res = munmap(addr, size);
	return res;
}
)M");

	tinykvm::Machine machine{binary, {.max_mem = MAX_MEMORY}};
	machine.setup_linux({"program"}, env);
	//machine.set_verbose_system_calls(true);
	machine.run(2.0f);
	REQUIRE(machine.return_value() == 666);

	struct Mapping
	{
		uint64_t addr;
		size_t size;

		bool exists(const std::vector<Mapping>& mappings) const
		{
			for (const auto& m : mappings)
			{
				if (m.addr == addr && m.size == size)
					return true;
			}
			return false;
		}
		bool within(const std::vector<Mapping>& mappings) const
		{
			for (const auto& m : mappings)
			{
				if (addr + size > m.addr && addr < m.addr + m.size)
					return true;
			}
			return false;
		}
		bool overlaps(const Mapping& other) const
		{
			return addr < other.addr + other.size && addr + size > other.addr;
		}
	};
	std::vector<Mapping> mappings;

	// Create a large number of mappings
	for (int i = 0; i < 10000; ++i)
	{
		// Make a random decision to either map or unmap
		const int decision = (rand() % 5);
		const bool do_mmap = decision == 0;
		const bool do_munmap = decision == 1;
		const bool do_mmap_within_mapping = decision == 2;
		const bool do_munmap_lower_half = decision == 3;
		const bool do_munmap_upper_half = decision == 4;
		if (do_mmap)
		{
			// Make a random page-aligned size
			const size_t size = (rand() % 1000 + 1) * 0x1000;
			machine.vmcall("do_mmap", size);
			const uint64_t guest_mmap_addr = machine.return_value();
			REQUIRE(guest_mmap_addr >= machine.mmap_start());

			// Add the mapping to the list
			Mapping m{guest_mmap_addr, size};
			const bool collision = m.within(mappings);
			if (collision)
			{
				fprintf(stderr, "Collision detected: %p -> %p (%zu)\n",
					(void*)m.addr, (void*)(m.addr + m.size), m.size);
				fprintf(stderr, "Collision with: ");
				for (const auto& m2 : mappings)
				{
					if (m2.overlaps(m))
						fprintf(stderr, "%p -> %p (%zu) ",
							(void*)m2.addr, (void*)(m2.addr + m2.size), m2.size);
				}
			}
			REQUIRE(!collision);
			mappings.push_back(m);
		}
		else if (do_munmap)
		{
			// Unmap a random mapping
			if (mappings.empty())
				continue;
			const size_t index = rand() % mappings.size();
			const auto& m = mappings[index];
			machine.vmcall("do_munmap", m.addr, m.size);
			REQUIRE(machine.return_value() == 0);

			// Remove the mapping from the list
			mappings.erase(mappings.begin() + index);
		}
		else if (do_mmap_within_mapping)
		{
			if (mappings.empty())
				continue;
			const size_t index = rand() % mappings.size();
			const auto& m = mappings[index];
			machine.vmcall("do_fixed_mmap", m.addr, m.size);
			const uint64_t guest_mmap_addr = machine.return_value();
			REQUIRE(guest_mmap_addr == m.addr);
		}
		else if (do_munmap_lower_half || do_munmap_upper_half)
		{
			if (mappings.empty())
				continue;
			const size_t index = rand() % mappings.size();
			auto& m = mappings[index];
			size_t remove_size = std::max(m.size / 2, size_t(0x1000));
			remove_size = (remove_size + 0xFFF) & ~0xFFF; // Align to page size
			const size_t new_size = m.size - remove_size;
			if (do_munmap_lower_half)
			{
				machine.vmcall("do_munmap", m.addr, remove_size);
				REQUIRE(machine.return_value() == 0);
				// Adjust or remove the mapping from the list
				if (new_size >= 0x1000)
				{
					m.addr += remove_size;
					m.size = new_size;
				}
				else
				{
					// Remove the mapping from the list
					mappings.erase(mappings.begin() + index);
				}
			}
			else // Upper half
			{
				const uint64_t remove_addr = m.addr + new_size;
				machine.vmcall("do_munmap", remove_addr, remove_size);
				REQUIRE(machine.return_value() == 0);
				// Adjust or remove the mapping from the list
				if (new_size >= 0x1000)
				{
					m.size = new_size;
				}
				else
				{
					// Remove the mapping from the list
					mappings.erase(mappings.begin() + index);
				}
			}
		}
	}
}
