#pragma once
#include <array>
#include <vector>
#include "common.hpp"
#include "virtual_mem.hpp"

namespace tinykvm {
struct Machine;
struct MemoryBanks;

struct MemoryBank {
	// This is 1x 2MB page (smallest x86 hugepage)
	static constexpr unsigned N_PAGES = 512;

	char*    mem;
	uint64_t addr;
	uint16_t       n_used = 0;
	const uint16_t n_pages;
	const uint16_t idx;
	std::array<uint64_t, N_PAGES> page_vaddr;
	MemoryBanks& banks;

	bool within(uint64_t a, uint64_t s) const noexcept {
		return (a >= addr) && (a + s <= addr + this->size());
	}
	char* at(uint64_t paddr) {
		return &mem[paddr - this->addr];
	}
	const char* at(uint64_t paddr) const {
		return &mem[paddr - this->addr];
	}
	uint64_t size() const noexcept { return n_pages * 4096; }
	bool empty() const noexcept { return n_used == n_pages; }
	struct Page {
		uint64_t* pmem;
		uint64_t  addr;
	};
	Page get_next_page(uint64_t vaddr);

	VirtualMem to_vmem() const noexcept;

	MemoryBank(MemoryBanks&, char*, uint64_t, uint16_t n, uint16_t idx);
	~MemoryBank();
};

struct MemoryBanks {
	MemoryBanks(Machine&, const MachineOptions&);

	MemoryBank& get_available_bank();
	void reset(const MachineOptions&);

	auto begin() { return m_mem.begin(); }
	auto end()   { return m_mem.end(); }
	auto begin() const { return m_mem.cbegin(); }
	auto end() const   { return m_mem.cend(); }

private:
	MemoryBank& allocate_new_bank(uint64_t addr);
	char* try_alloc(size_t N);

	std::vector<MemoryBank> m_mem;
	Machine& m_machine;
	const uint64_t m_arena_begin;
	uint64_t m_arena_next;
	const uint16_t m_idx_begin;
	uint16_t m_idx;
	uint16_t m_search = 0;
	const bool m_using_hugepages = false;
	uint32_t m_num_pages = 0;
	/* Max number of pages in all the banks */
	uint32_t m_max_pages;

	friend struct MemoryBank;
};

}
