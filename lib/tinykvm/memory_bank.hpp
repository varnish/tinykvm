#pragma once
#include <cstdint>
#include <vector>

namespace tinykvm {

struct MemoryBank {
	char*       mem;
	uint64_t	addr;
	uint16_t    n_used;
	uint16_t    n_pages;

	bool empty() const noexcept { return n_used == n_pages; }
	struct Page {
		char*    mem;
		uint64_t addr;
	};
	Page get_next_page();
};

struct MemoryBanks {
	static const unsigned N_PAGES = 16;

	void* get_page();
	MemoryBank& get_available_bank(uint64_t next_addr);

private:
	MemoryBank& allocate_new_bank(uint64_t addr);

	std::vector<MemoryBank> m_mem;
};

}
