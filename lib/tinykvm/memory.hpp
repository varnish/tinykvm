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
	static constexpr uint64_t PAGE_SIZE = 4096;

	Machine& machine;
	uint64_t physbase;
	uint64_t safebase;
	uint64_t page_tables;
	/* Linear memory */
	char*  ptr;
	size_t size;
	bool   owned = true;
	/* Use memory banks only for page tables, write directly
	   to main memory. Used with is_forkable_master(). */
	bool   main_memory_writes = false;
	/* Dynamic page memory */
	MemoryBanks banks; // fault-in memory banks
	/* SMP mutex */
	std::mutex mtx_smp;

	/* Unsafe */
	bool within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= physbase) && (addr + asize <= physbase + this->size);
	}
	char* at(uint64_t addr, size_t asize = 8);
	const char* at(uint64_t addr, size_t asize = 8) const;
	uint64_t* page_at(uint64_t addr) const;
	/* Safe */
	bool safely_within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= safebase) && (addr + asize <= physbase + this->size);
	}
	char* safely_at(uint64_t addr, size_t asize);
	std::string_view view(uint64_t addr, size_t asize) const;

	char *get_userpage_at(uint64_t addr) const;
	char *get_kernelpage_at(uint64_t addr) const;
	char *get_writable_page(uint64_t addr, bool zeroes);
	MemoryBank::Page new_page(uint64_t vaddr);

	bool compare(const vMemory& other);

	VirtualMem vmem() const;

	[[noreturn]] static void memory_exception(const char*, uint64_t, uint64_t);
	void fork_reset(const MachineOptions&);
	void fork_reset(const vMemory& other, const MachineOptions&);
	static vMemory New(Machine&, const MachineOptions&, uint64_t phys, uint64_t safe, size_t size);
	/* Returns true when this VM uses banking only to make page tables writable
	   again in order to support itself. It has already been made forkable. */
	bool is_forkable_master() const noexcept;

	/* Create new identity-mapped memory regions */
	vMemory(Machine&, const MachineOptions&, uint64_t, uint64_t, char*, size_t, bool = true);
	/* Loan memory from another machine */
	vMemory(Machine&, const MachineOptions&, const vMemory& other);
	~vMemory();
private:
	using AllocationResult = std::tuple<char*, size_t>;
	static AllocationResult allocate_mapped_memory(const MachineOptions&, size_t size);
};

}
