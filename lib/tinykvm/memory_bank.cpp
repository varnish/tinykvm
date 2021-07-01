#include "memory_bank.hpp"

#include "common.hpp"
#include <cassert>
#include <malloc.h>

namespace tinykvm {

MemoryBanks::MemoryBanks(Machine& machine)
	: m_machine { machine },
	  m_arena_next { 0x700000000 },
	  m_idx { 2 }
{
}

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
MemoryBank& MemoryBanks::get_available_bank()
{
	if (!m_mem.empty()) {
		auto& last = m_mem.back();
		if (!last.empty()) {
			return last;
		}
	}
	auto& bank = this->allocate_new_bank(m_arena_next);
	m_arena_next += bank.n_pages * 4096;
	return bank;
}

MemoryBank::Page MemoryBank::get_next_page()
{
	assert(n_used < n_pages);
	uint64_t offset = 4096 * n_used;
	n_used++;
	return {(uint64_t *)mem + offset, addr + offset};
}

} // tinykvm
