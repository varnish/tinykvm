#include "memory_bank.hpp"

#include "common.hpp"
#include "machine.hpp"
#include "virtual_mem.hpp"
#include <cassert>
#include <cstring>
#include <malloc.h>
#include <sys/mman.h>

namespace tinykvm {

MemoryBanks::MemoryBanks(Machine& machine, const MachineOptions& options)
	: m_machine { machine },
	  m_arena_begin { 0x7000000000 },
	  m_arena_next { m_arena_begin },
	  m_idx_begin { 2 },
	  m_idx { m_idx_begin },
	  m_using_hugepages { options.hugepages }
{
	this->set_max_pages(options.max_cow_mem / vMemory::PageSize());
}
void MemoryBanks::set_max_pages(size_t new_max)
{
	this->m_max_pages = new_max;
	//fprintf(stderr, "max_pages: %zu/%zu\n", m_mem.size(), new_max);
	/* Reserve the maximum number of banks possible.
	   We have to + 1 to make sure it's rounded up, avoiding
	   any possible reallocations close to being out of memory.
	   NOTE: DO NOT modify this! Needs deque behavior. */
	m_mem.reserve(m_max_pages / MemoryBank::N_PAGES + 1);
}

char* MemoryBanks::try_alloc(size_t N)
{
	char* ptr = (char*)MAP_FAILED;
	if (this->m_using_hugepages && N == 512) {
		ptr = (char*) mmap(NULL, N * vMemory::PageSize(), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_HUGETLB, -1, 0);
	}
	if (ptr == MAP_FAILED) {
		return (char*) mmap(NULL, N * vMemory::PageSize(), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	}
	return ptr;
}

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr)
{
	size_t pages = MemoryBank::N_PAGES;
	char* mem = this->try_alloc(pages);
	if (mem == nullptr) {
		pages = 4;
		mem = this->try_alloc(pages);
	}

	const size_t size = pages * vMemory::PageSize();
	if (mem != nullptr) {
		m_mem.emplace_back(*this, mem, addr, pages, m_idx);

		VirtualMem vmem { addr, mem, size };
		//printf("Installing memory %u at 0x%lX from 0x%lX, %zu pages\n",
		//	m_idx, addr, (uintptr_t) mem, N_PAGES);
		m_machine.install_memory(m_idx++, vmem, false);

		return m_mem.back();
	}
	throw MemoryException("Failed to allocate memory bank", 0, size);
}
MemoryBank& MemoryBanks::get_available_bank(size_t pages)
{
	/* Hugepages are 512 4k pages, and consume a whole bank, right now. */
	for (unsigned idx = 0; idx < m_mem.size(); idx++) {
		auto& bank = m_mem.at(idx);
		if (bank.room_for(pages)) {
			return bank;
		}
	}
	/* Allocate new memory bank if we are not maxing out memory */
	if (m_num_pages < m_max_pages) {
		//printf("Allocating new bank at 0x%lX with total pages %u\n",
		//	m_arena_next, m_num_pages + MemoryBank::N_PAGES);
		auto& bank = this->allocate_new_bank(m_arena_next);
		m_num_pages += bank.n_pages;
		m_arena_next += bank.size();
		return bank;
	}
	throw MemoryException("Out of working memory", m_num_pages, m_max_pages);
}
void MemoryBanks::reset(const MachineOptions& options)
{
	/* Reset page usage, but keep banks */
	for (auto& bank : m_mem) {
		bank.n_used = 0;
	}
	m_max_pages = options.max_cow_mem / vMemory::PageSize();

	/* The limit feature is off when reset_free_work_mem == 0. */
	size_t limit_pages = options.reset_free_work_mem / vMemory::PageSize();
	if (limit_pages > 0)
	{
		size_t final_banks = std::max(size_t(1u), limit_pages / MemoryBank::N_PAGES);
		/* Erase the last N elements after final_banks */
		while (final_banks < m_mem.size()) {
			this->m_idx--;
			m_machine.delete_memory(this->m_idx);
			m_mem.pop_back();
		}
	}
}

MemoryBank::MemoryBank(MemoryBanks& b, char* p, uint64_t a, uint16_t np, uint16_t x)
	: mem(p), addr(a), n_pages(np), idx(x), banks(b)
{}
MemoryBank::~MemoryBank()
{
	munmap(this->mem, this->n_pages * vMemory::PageSize());
}

MemoryBank::Page MemoryBank::get_next_page(size_t pages)
{
	assert(n_used + pages <= n_pages);
	uint64_t offset = vMemory::PageSize() * n_used;
	n_used += pages;
	return {(uint64_t *)&mem[offset], addr + offset, pages * vMemory::PageSize()};
}

VirtualMem MemoryBank::to_vmem() const noexcept
{
	return VirtualMem {this->addr, this->mem, this->size()};
}

} // tinykvm
