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
	  m_arena_begin { 0x7000000000 },
	  m_idx_begin { 2 },
	  m_arena_next { m_arena_begin },
	  m_idx { m_idx_begin }
{
}

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr)
{
	const size_t size = N_PAGES * PAGE_SIZE;
	char* mem = nullptr;
	if (page_allocator == nullptr) {
		mem = (char *)memalign(PAGE_SIZE, size);
	} else {
		mem = this->page_allocator(N_PAGES);
	}

	if (mem != nullptr) {
		m_mem.emplace_back(*this, mem, addr, N_PAGES, m_idx);

		VirtualMem vmem { addr, mem, size };
		//printf("Installing memory at 0x%lX from 0x%lX, %zu pages\n",
		//	addr, (uintptr_t) mem, N_PAGES);
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
void MemoryBanks::reset()
{
	if (page_allocator != nullptr)
	{
		/* With a custom allocator, we reset everything */
		while (!m_mem.empty()) {
			m_machine.delete_memory(m_mem.back().idx);
			m_mem.pop_back();
		}
		m_idx = m_idx_begin;
	}
	else {
		/* We will attempt to keep one memory bank */
		while (m_mem.size() > 1) {
			m_machine.delete_memory(m_mem.back().idx);
			m_mem.pop_back();
		}
		if (!m_mem.empty()) {
			m_mem.back().n_used = 0;
			m_idx = m_mem.back().idx + 1;
		} else {
			m_idx = m_idx_begin;
		}
	}
	m_arena_next = m_arena_begin;
}

MemoryBank::MemoryBank(MemoryBanks& b, char* p, uint64_t a, uint16_t np, uint16_t x)
	: mem(p), addr(a), n_pages(np), idx(x), banks(b)
{}
MemoryBank::~MemoryBank()
{
	if (banks.page_deallocator != nullptr) {
		banks.page_deallocator(this->mem);
	} else {
		std::free(this->mem);
	}
}

MemoryBank::Page MemoryBank::get_next_page()
{
	assert(n_used < n_pages);
	uint64_t offset = PAGE_SIZE * n_used;
	n_used++;
	return {(uint64_t *)&mem[offset], addr + offset};
}

} // tinykvm
