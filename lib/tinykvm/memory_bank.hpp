#pragma once
#include <cstdint>
#include <vector>

namespace tinykvm {
struct Machine;

struct MemoryBank {
	char*       mem;
	uint64_t	addr;
	uint16_t    n_used;
	uint16_t    n_pages;

	bool empty() const noexcept { return n_used == n_pages; }
	struct Page {
		uint64_t* pmem;
		uint64_t  addr;
	};
	Page get_next_page();
};

struct MemoryBanks {
	static const unsigned N_PAGES = 16;

	MemoryBanks(Machine&);

	MemoryBank& get_available_bank();

private:
	MemoryBank& allocate_new_bank(uint64_t addr);

	std::vector<MemoryBank> m_mem;
	Machine& m_machine;
	uint64_t m_arena_next;
	size_t   m_idx;
};

}
