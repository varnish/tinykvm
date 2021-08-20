#include "memory_bank.hpp"

#include "common.hpp"
#include "machine.hpp"
#include "virtual_mem.hpp"
#include <cassert>
#include <cstring>
#include <malloc.h>
#define PAGE_SIZE   0x1000

namespace tinykvm {

MemoryBanks::MemoryBanks(Machine& machine, const MachineOptions& options)
	: m_machine { machine },
	  m_arena_begin { 0x7000000000 },
	  m_arena_next { m_arena_begin },
	  m_idx_begin { 2 },
	  m_idx { m_idx_begin },
	  m_max_pages { options.max_cow_mem / PAGE_SIZE }
{
	/* Reserve the maximum number of banks possible.
	   We have to + 1 to make sure it's rounded up, avoiding
	   any possible reallocations close to being out of memory.
	   NOTE: DO NOT modify this! Needs deque behavior. */
	m_mem.reserve(m_max_pages / MemoryBank::N_PAGES + 1);
}

char* MemoryBanks::try_alloc(size_t N)
{
	return (char *)memalign(PAGE_SIZE, N * PAGE_SIZE);
}

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr)
{
	size_t pages = MemoryBank::N_PAGES;
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
	for (; m_search < m_mem.size(); m_search++) {
		auto& bank = m_mem.at(m_search);
		if (!bank.empty()) {
			return bank;
		}
	}
	/* Allocate new memory bank if we are not maxing out memory */
	if (m_num_pages < m_max_pages) {
		auto& bank = this->allocate_new_bank(m_arena_next);
		m_num_pages += bank.n_pages;
		m_arena_next += bank.size();
		return bank;
	}
	throw MemoryException("Out of memory", m_num_pages, m_max_pages);
}
void MemoryBanks::reset(const MachineOptions& options)
{
	/* Reset page usage, but keep banks */
	for (auto& bank : m_mem) {
		bank.n_used = 0;
	}
	m_search = 0;
	m_max_pages = options.max_cow_mem / PAGE_SIZE;
}

MemoryBank::MemoryBank(MemoryBanks& b, char* p, uint64_t a, uint16_t np, uint16_t x)
	: mem(p), addr(a), n_pages(np), idx(x), banks(b)
{}
MemoryBank::~MemoryBank()
{
	free(this->mem);
}

MemoryBank::Page MemoryBank::get_next_page(uint64_t vaddr)
{
	assert(n_used < n_pages);
	uint64_t offset = PAGE_SIZE * n_used;
	page_vaddr.at(n_used) = vaddr;
	n_used++;
	return {(uint64_t *)&mem[offset], addr + offset};
}

VirtualMem MemoryBank::to_vmem() const noexcept
{
	return VirtualMem {this->addr, this->mem, this->size()};
}

} // tinykvm
