#pragma once
#include "common.hpp"
#include "memory_bank.hpp"
#include "virtual_mem.hpp"
#include <cstddef>
#include <mutex>
#include <string_view>

namespace tinykvm {
struct Machine;
struct MemoryBanks;

struct vMemory {
	static constexpr uint64_t PageSize() {
		return 4096u;
	}

	Machine& machine;
	uint64_t physbase;
	uint64_t safebase;
	uint64_t page_tables;
	/* Optional executable memory range */
	uint64_t vmem_exec_begin = 0;
	uint64_t vmem_exec_end   = 0;
	/* Counter for the number of pages that have been unlocked
	   in the main memory. */
	size_t unlocked_pages = 0;
	/* Linear memory */
	char*  ptr;
	size_t size;
	bool   owned = true;
	/* Use memory banks only for page tables, write directly
	   to main memory. Used with is_forkable_master(). */
	bool   main_memory_writes = false;
	/* Split into small pages (4K) when reaching a leaf hugepage. */
	bool   split_hugepages = true;
	/* Executable heap */
	bool   executable_heap = false;
	/* Dynamic page memory */
	MemoryBanks banks; // fault-in memory banks
	/* SMP mutex */
	std::mutex mtx_smp;
	bool smp_guards_enabled = false;

	/* Unsafe */
	bool within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= physbase) && (addr + asize <= physbase + this->size) && (addr <= addr + asize);
	}
	char* at(uint64_t addr, size_t asize = 8);
	const char* at(uint64_t addr, size_t asize = 8) const;
	uint64_t* page_at(uint64_t addr) const;
	/* Safe */
	bool safely_within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= safebase) && (addr + asize <= physbase + this->size);
	}
	const char* safely_at(uint64_t addr, size_t asize) const;
	char* safely_at(uint64_t addr, size_t asize);
	std::string_view view(uint64_t addr, size_t asize) const;

	char *get_userpage_at(uint64_t addr) const;
	char *get_kernelpage_at(uint64_t addr) const;
	char *get_writable_page(uint64_t addr, uint64_t flags, bool zeroes);
	MemoryBank::Page new_page();
	MemoryBank::Page new_hugepage();

	bool compare(const vMemory& other);
	/* When a main VM has direct memory writes enabled, it can
	   write directly to its own memory, but in order to constrain
	   the memory usage, we need to keep track of the number of
	   pages that have been unlocked. */
	void increment_unlocked_pages(size_t pages);
	size_t unlocked_memory_pages() const noexcept {
		return unlocked_pages;
	}

	VirtualMem vmem() const;

	[[noreturn]] static void memory_exception(const char*, uint64_t, uint64_t);
	void fork_reset(const MachineOptions&);
	void fork_reset(const vMemory& other, const MachineOptions&);
	static vMemory New(Machine&, const MachineOptions&, uint64_t phys, uint64_t safe, size_t size);
	/* Returns true when this VM uses banking only to make page tables writable
	   again in order to support itself. It has already been made forkable. */
	bool is_forkable_master() const noexcept;

	uint64_t expectedUsermodeFlags() const noexcept;

	/* Create new identity-mapped memory regions */
	vMemory(Machine&, const MachineOptions&, uint64_t, uint64_t, char*, size_t, bool = true);
	/* Loan memory from another machine */
	vMemory(Machine&, const MachineOptions&, const vMemory& other);
	~vMemory();

	static uint64_t overaligned_memsize(uint64_t size) {
		static constexpr uint64_t ALIGN = 1ULL << 21;
		return (size + (ALIGN - 1)) & ~(ALIGN - 1);
	}
private:
	using AllocationResult = std::tuple<char*, size_t>;
	static AllocationResult allocate_mapped_memory(const MachineOptions&, size_t size);
};

}
