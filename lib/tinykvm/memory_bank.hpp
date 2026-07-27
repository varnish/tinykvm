#pragma once
#include <array>
#include <vector>
#include "common.hpp"
#include "virtual_mem.hpp"

namespace tinykvm {
struct Machine;
struct MemoryBanks;

struct MemoryBank {
	// This is 1x 2MB page (second-level amd64 page)
	static constexpr unsigned N_PAGES = 4u * 512;
	static constexpr unsigned N_HUGEPAGES = 512u;

	char*    mem;
	uint64_t addr;
	uint32_t       n_used = 0;
	uint32_t       n_dirty = 0;
	const uint32_t n_pages;
	const uint16_t idx;
	/* Whether `mem` is this bank's own mmap, to be released with the bank, or
	   a window into a VM group seat's arena partition, which the group keeps
	   mapped for the lifetime of the seat. Cached at construction rather than
	   read back from `banks` in the destructor: the banks are a member of
	   MemoryBanks and are destroyed as part of destroying it, at which point
	   its other members have already been destroyed and reading them is UB. */
	const bool owns_mmap;
	MemoryBanks& banks;

	bool within(uint64_t a, uint64_t s) const noexcept {
		return (a >= addr) && (a + s <= addr + this->size()) && (a <= a + s);
	}
	char* at(uint64_t paddr) {
		return &mem[paddr - this->addr];
	}
	const char* at(uint64_t paddr) const {
		return &mem[paddr - this->addr];
	}
	uint64_t size() const noexcept { return uint64_t(n_pages) * 4096; }
	uint64_t dirty_size() const noexcept { return uint64_t(n_dirty) * 4096; }
	bool empty() const noexcept { return n_used == n_pages; }
	bool room_for(size_t pages) const noexcept;
	struct Page {
		uint64_t* pmem;
		uint64_t  addr;
		size_t    size;
		bool      dirty;
	};
	Page get_next_page(size_t n_pages);

	VirtualMem to_vmem() const noexcept;

	MemoryBank(MemoryBanks&, char*, uint64_t, uint32_t n, uint16_t idx, bool owns_mmap);
	~MemoryBank();
};

struct MemoryBanks {
	static constexpr unsigned FIRST_BANK_IDX = 2;
#ifdef TINYKVM_ARCH_ARM64
	static constexpr uint64_t ARENA_BASE_ADDRESS = 0x80000000;
#else
	static constexpr uint64_t ARENA_BASE_ADDRESS = 0x7000000000;
#endif

	MemoryBanks(Machine&, const MachineOptions&);
	void init_from(const MemoryBanks&);
	/* Pooled mode: banks are carved out of a pre-mapped, pre-installed
	   window at fixed offsets instead of being mmap'ed and installed one at
	   a time. @gpa/@hva/@size describe the VM group seat's arena partition,
	   and @max_cow_ceiling is the group's frozen working-memory ceiling,
	   which a later reset() may not raise. */
	void init_from_partition(uint64_t gpa, char* hva, uint64_t size,
		uint32_t max_cow_ceiling);
	bool is_partitioned() const noexcept { return m_partition_hva != nullptr; }
	/* Bytes of the partition handed out to banks so far. */
	uint64_t partition_used() const noexcept { return m_arena_next - m_arena_begin; }

	MemoryBank& get_available_bank(size_t n_pages);
	void reset(const MachineOptions&);
	void set_max_pages(size_t new_max, size_t new_hugepages);
	size_t max_pages() const noexcept { return m_max_pages; }
	uint64_t arena_begin() const noexcept { return m_arena_begin; }
	int allocate_region_idx() {
		return m_idx++;
	}

	bool using_hugepages() const noexcept { return m_hugepage_pages > 0; }
	size_t banks_with_hugepages() const noexcept { return m_hugepage_pages / MemoryBank::N_PAGES; }

	auto begin() { return m_mem.begin(); }
	auto end()   { return m_mem.end(); }
	auto begin() const { return m_mem.cbegin(); }
	auto end() const   { return m_mem.cend(); }
	size_t size() const noexcept { return m_mem.size(); }
	const MemoryBank& at(size_t i) const { return m_mem.at(i); }

private:
	MemoryBank& allocate_new_bank(uint64_t addr, unsigned pages);
	char* try_alloc(size_t N, bool try_hugepages);

	std::vector<MemoryBank> m_mem;
	Machine& m_machine;
	uint64_t m_arena_begin;
	uint64_t m_arena_next;
	/* Pooled mode: the seat's window, and the hard end of the partition. */
	char*    m_partition_hva = nullptr;
	uint64_t m_partition_end = 0;
	uint32_t m_max_ceiling_pages = 0;
	uint16_t m_idx;
	/* Number of initial banks that will allocate backing memory using hugepages */
	uint32_t m_hugepage_pages = 0;
	uint32_t m_num_pages = 0;
	/* Max number of pages in all the banks */
	uint32_t m_max_pages;

	friend struct MemoryBank;
};

}
