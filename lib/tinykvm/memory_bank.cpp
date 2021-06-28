#include "memory_bank.hpp"

#include "common.hpp"
#include <cassert>
#include <malloc.h>

namespace tinykvm {

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr)
{
	const size_t size = N_PAGES * 4096;
	char* mem = (char *)memalign(size, 4096);

	if (mem != nullptr) {
		m_mem.push_back({mem, addr, 0, N_PAGES});
		return m_mem.back();
	}
	throw MemoryException("Failed to allocate memory bank", 0, size);
}
MemoryBank& MemoryBanks::get_available_bank(uint64_t next_addr)
{
	if (!m_mem.empty()) {
		auto& last = m_mem.back();
		if (!last.empty()) {
			return last;
		}
	}
	return this->allocate_new_bank(next_addr);
}

MemoryBank::Page MemoryBank::get_next_page()
{
	assert(n_used < n_pages);
	uint64_t offset = 4096 * n_used;
	n_used++;
	return {mem + offset, addr + offset};
}

} // tinykvm
