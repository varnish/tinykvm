#pragma once
#include <cstdint>
#include <functional>
#include <vector>

namespace tinykvm {
struct Machine;
struct MemoryBanks;

struct MemoryBank {
	char*    mem;
	uint64_t addr;
	uint16_t       n_used = 0;
	const uint16_t n_pages;
	const uint16_t idx;
	MemoryBanks& banks;

	bool within(uint64_t a, uint64_t s) const noexcept {
		return (a >= addr) && (a + s <= addr + this->size());
	}
	char* at(uint64_t vaddr) {
		return &mem[vaddr - this->addr];
	}
	const char* at(uint64_t vaddr) const {
		return &mem[vaddr - this->addr];
	}
	uint64_t size() const noexcept { return n_pages * 4096; }
	bool empty() const noexcept { return n_used == n_pages; }
	struct Page {
		uint64_t* pmem;
		uint64_t  addr;
	};
	Page get_next_page();

	MemoryBank(MemoryBanks&, char*, uint64_t, uint16_t n, uint16_t idx);
	~MemoryBank();
};

struct MemoryBanks {
	static constexpr unsigned N_PAGES = 16;

	MemoryBanks(Machine&);

	MemoryBank& get_available_bank();
	void reset();

	auto begin() { return m_mem.begin(); }
	auto end()   { return m_mem.end(); }
	auto begin() const { return m_mem.cbegin(); }
	auto end() const   { return m_mem.cend(); }

	std::function<char*(size_t N)> page_allocator = nullptr;
	std::function<void(char*)> page_deallocator = nullptr;

private:
	MemoryBank& allocate_new_bank(uint64_t addr);
	char* try_alloc(size_t N);

	std::vector<MemoryBank> m_mem;
	Machine& m_machine;
	const uint64_t m_arena_begin;
	const size_t   m_idx_begin;
	uint64_t m_arena_next;
	size_t   m_idx;
};

}
