#include "memory_bank.hpp"

#include "common.hpp"
#include "machine.hpp"
#include "virtual_mem.hpp"
#include <cassert>
#include <cstring>
#include <malloc.h>
#include <sys/mman.h>

namespace tinykvm {
static constexpr bool VERBOSE_MEMORY_BANK = false;

MemoryBanks::MemoryBanks(Machine& machine, const MachineOptions& options)
	: m_machine { machine },
	  m_arena_begin { ARENA_BASE_ADDRESS },
	  m_arena_next { m_arena_begin },
	  m_idx { FIRST_BANK_IDX }
{
	if (options.vmem_base_address != 0 || options.dylink_address_hint >= 0x1000000000) {
		this->m_arena_begin += 0x800000000;
		this->m_arena_next = m_arena_begin;
	}
	this->set_max_pages(options.max_cow_mem / vMemory::PageSize(),
		options.hugepages_arena_size / vMemory::PageSize());
}
void MemoryBanks::init_from(const MemoryBanks& other)
{
	this->m_arena_begin = other.m_arena_begin;
	this->m_arena_next = other.m_arena_next;
	// Verify that there aren't any existing banks allocated
	if (!this->m_mem.empty()) {
		throw MemoryException("Cannot init_from() when banks are already allocated (arena_begin will be wrong)",
			this->m_arena_begin, m_mem[0].addr);
	}
}
void MemoryBanks::set_max_pages(size_t new_max, size_t new_hugepages)
{
	this->m_max_pages = new_max;
	this->m_hugepage_pages = new_hugepages;
	if (this->m_hugepage_pages % MemoryBank::N_HUGEPAGES != 0) {
		throw MemoryException("Hugepages size must be multiple of 2MB",
			this->m_hugepage_pages * vMemory::PageSize(), MemoryBank::N_HUGEPAGES * vMemory::PageSize());
	}
	if constexpr (VERBOSE_MEMORY_BANK) {
		printf("Memory banks: %u pages, %u hugepages\n",
			m_max_pages, m_hugepage_pages);
	}
	/* Reserve the maximum number of banks possible.
	   NOTE: DO NOT modify this! Needs deque behavior. */
	const size_t banks = (m_max_pages + MemoryBank::N_PAGES - 1) / MemoryBank::N_PAGES;
	const size_t new_banks = banks + 1u + (this->using_hugepages() ? 1u : 0u);
	m_mem.reserve(new_banks);
}

char* MemoryBanks::try_alloc(size_t N, bool try_hugepages)
{
	char* ptr = (char*)MAP_FAILED;
	if (try_hugepages && N == 512) {
		ptr = (char*) mmap(NULL, N * vMemory::PageSize(), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_HUGETLB, -1, 0);
	}
	if (ptr == MAP_FAILED) {
		return (char*) mmap(NULL, N * vMemory::PageSize(), PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	}
	return ptr;
}

MemoryBank& MemoryBanks::allocate_new_bank(uint64_t addr, unsigned pages)
{
	if constexpr (VERBOSE_MEMORY_BANK) {
		printf("Allocating new memory bank at 0x%lX with %u pages\n", addr, pages);
	}
	const bool try_hugepages = m_mem.empty() && this->using_hugepages();
	if (try_hugepages) {
		pages = m_hugepage_pages;
	}
	char* mem = this->try_alloc(pages, try_hugepages);
	if (mem == nullptr) {
		pages = 16;
		mem = this->try_alloc(pages, false);
		this->m_hugepage_pages = 0;
	}

	const size_t size = pages * vMemory::PageSize();
	if (mem != nullptr) {
		m_mem.emplace_back(*this, mem, addr, pages, m_idx);

		VirtualMem vmem { addr, mem, size };
		if constexpr (VERBOSE_MEMORY_BANK) {
			printf("  Allocated bank %zu (slot %u) at 0x%lX with %u pages (%zu KiB)\n",
				m_mem.size(), m_idx, addr, pages, size >> 10);
		}
		m_machine.install_memory(m_idx++, vmem, false);

		return m_mem.back();
	}
	throw MemoryException("Failed to allocate memory bank", 0, size);
}
MemoryBank& MemoryBanks::get_available_bank(size_t pages)
{
	if constexpr (VERBOSE_MEMORY_BANK) {
		printf("Requesting %zu working memory pages\n", pages);
	}
	/* Try to find room for the pages. */
	for (unsigned idx = 0; idx < m_mem.size(); idx++) {
		auto& bank = m_mem.at(idx);
		if (bank.room_for(pages)) {
			if constexpr (VERBOSE_MEMORY_BANK) {
				printf("Reusing bank slot=%u at 0x%lX with %zu/%u used pages\n",
					bank.idx, bank.addr, bank.n_used + pages, bank.n_pages);
			}
			return bank;
		}
	}
	/* Allocate new memory bank if we are not maxing out memory */
	if (m_num_pages < m_max_pages) {
		if constexpr (VERBOSE_MEMORY_BANK) {
			printf("Allocating new bank at 0x%lX with total pages %u/%u\n",
				m_arena_next, m_num_pages, m_max_pages);
		}
		auto& bank = this->allocate_new_bank(m_arena_next, MemoryBank::N_PAGES);
		m_num_pages += bank.n_pages;
		m_arena_next += bank.size();
		return bank;
	}
	/* Find room but with possible fragmentation. */
	if (pages == MemoryBank::N_HUGEPAGES) {
		for (unsigned idx = 0; idx < m_mem.size(); idx++) {
			auto& bank = m_mem.at(idx);
			const unsigned n_used = (bank.n_used + MemoryBank::N_HUGEPAGES - 1) & ~(MemoryBank::N_HUGEPAGES - 1);
			if (n_used + pages <= bank.n_pages) {
				if constexpr (VERBOSE_MEMORY_BANK) {
					printf("Reusing bank (fragmented) slot=%u at 0x%lX with %zu/%u used pages\n",
						bank.idx, bank.addr, n_used + pages, bank.n_pages);
				}
				bank.n_used = n_used;
				return bank;
			}
		}
	}
	if constexpr (VERBOSE_MEMORY_BANK) {
		fprintf(stderr, "Out of working memory requesting %zu pages, %u vs %u max pages\n",
			pages, m_num_pages, m_max_pages);
	}
	throw MemoryException("Out of working memory",
		m_num_pages * vMemory::PageSize(), m_max_pages * vMemory::PageSize(), true);
}
void MemoryBanks::reset(const MachineOptions& options)
{
	/* New maximum pages total in banks. */
	this->m_max_pages = options.max_cow_mem / vMemory::PageSize();

	/* Free memory belonging to banks after the free limit. */
	//size_t limit_pages = options.reset_free_work_mem / vMemory::PageSize();

	/* Instead of removing the banks, give memory back to kernel */
	for (size_t i = 1u; i < m_mem.size(); i++) {
		/* WARNING: MADV_FREE *does not* immediately free, so use MADV_DONTNEED instead. */
		if (m_mem[i].dirty_size() > 0)
			madvise(m_mem[i].mem, m_mem[i].dirty_size(), MADV_DONTNEED);
		m_mem[i].n_dirty = 0;
	}

	/* Reset page usage for remaining banks */
	for (auto& bank : m_mem) {
		bank.n_used = 0;
	}
}

MemoryBank::MemoryBank(MemoryBanks& b, char* p, uint64_t a, uint32_t np, uint16_t x)
	: mem(p), addr(a), n_pages(np), idx(x), banks(b)
{
	if constexpr (VERBOSE_MEMORY_BANK) {
		printf("Created memory bank slot=%u at 0x%lX with %u pages (%zu KiB)\n",
			idx, addr, n_pages, n_pages * vMemory::PageSize() >> 10);
	}
}
MemoryBank::~MemoryBank()
{
	munmap(this->mem, this->n_pages * vMemory::PageSize());
}

bool MemoryBank::room_for(size_t pages) const noexcept {
	if (pages == N_HUGEPAGES) {
		// It's a hugepage, which must be aligned
		if (this->n_used % N_HUGEPAGES != 0) {
			return false;
		}
	}
	return n_used + pages <= n_pages;
}
MemoryBank::Page MemoryBank::get_next_page(size_t pages)
{
	assert(this->n_used + pages <= this->n_pages);
	const uint64_t offset = vMemory::PageSize() * this->n_used;
	const bool dirty = this->n_used < this->n_dirty;
	this->n_used += pages;
	this->n_dirty = std::max(this->n_used, this->n_dirty);
	return {(uint64_t *)&mem[offset], addr + offset, pages * vMemory::PageSize(), dirty};
}

VirtualMem MemoryBank::to_vmem() const noexcept
{
	return VirtualMem {this->addr, this->mem, this->size()};
}

} // tinykvm
