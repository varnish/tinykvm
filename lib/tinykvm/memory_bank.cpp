#include "memory_bank.hpp"

#include "common.hpp"
#include "machine.hpp"
#include "virtual_mem.hpp"
#include <cassert>
#include <malloc.h>
#define PAGE_SIZE   0x1000

namespace tinykvm {

MemoryBanks::MemoryBanks(Machine& machine)
	: m_machine { machine },
	  m_arena_next { 0x7000000000 },
	  m_idx { 2 }
{
}

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr)
{
	const size_t size = N_PAGES * PAGE_SIZE;
	char* mem = (char *)memalign(PAGE_SIZE, size);

	if (mem != nullptr) {
		m_mem.push_back({mem, addr, 0, N_PAGES});

		VirtualMem vmem { addr, mem, size };
		printf("Installing memory at 0x%lX from 0x%lX, %zu pages\n",
			addr, (uintptr_t) mem, N_PAGES);
		m_machine.install_memory(m_idx++, vmem);

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
	m_arena_next += bank.size();
	return bank;
}

MemoryBank::Page MemoryBank::get_next_page()
{
	assert(n_used < n_pages);
	uint64_t offset = PAGE_SIZE * n_used;
	n_used++;
	return {(uint64_t *)&mem[offset], addr + offset};
}

} // tinykvm
