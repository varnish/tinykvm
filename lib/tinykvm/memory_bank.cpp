#include "memory_bank.hpp"

#include "common.hpp"
#include "machine.hpp"
#include "virtual_mem.hpp"
#include <cassert>
#include <cstring>
#include <malloc.h>
#define PAGE_SIZE   0x1000

namespace tinykvm {

MemoryBanks::MemoryBanks(Machine& machine)
	: m_machine { machine },
	  m_arena_begin { 0x7000000000 },
	  m_arena_next { m_arena_begin },
	  m_idx_begin { 2 },
	  m_idx { m_idx_begin }
{
}

char* MemoryBanks::try_alloc(size_t N)
{
	if (page_allocator == nullptr) {
		return (char *)memalign(PAGE_SIZE, N * PAGE_SIZE);
	} else {
		return this->page_allocator(N);
	}
}

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr)
{
	size_t pages = N_PAGES;
	char* mem = this->try_alloc(pages);
	if (mem == nullptr) {
		pages = 4;
		mem = this->try_alloc(pages);
	}

	const size_t size = pages * PAGE_SIZE;
	if (mem != nullptr) {
		m_mem.emplace_back(*this, mem, addr, pages, m_idx);

		VirtualMem vmem { addr, mem, size };
		//printf("Installing memory %u at 0x%lX from 0x%lX, %zu pages\n",
		//	m_idx, addr, (uintptr_t) mem, N_PAGES);
		m_machine.install_memory(m_idx++, vmem);

		return m_mem.back();
	}
	throw MemoryException("Failed to allocate memory bank", 0, size);
}
MemoryBank& MemoryBanks::get_available_bank()
{
	if (!m_mem.empty()) {
		for (; m_search < m_mem.size(); m_search++) {
			auto& bank = m_mem.at(m_search);
			if (!bank.empty()) {
				return bank;
			}
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
		/* We always start fresh at arena start */
		m_arena_next = m_arena_begin;
	}
	else {
		/* Reset page usage, but keep banks */
		for (auto& bank : m_mem) {
			bank.n_used = 0;
		}
		m_idx = m_idx_begin + m_mem.size();
	}
	m_search = 0;
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

VirtualMem MemoryBank::to_vmem() const noexcept
{
	return VirtualMem {this->addr, this->mem, this->size()};
}

} // tinykvm
