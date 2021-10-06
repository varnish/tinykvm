#pragma once
#include "common.hpp"
#include "memory_bank.hpp"
#include "virtual_mem.hpp"
#include <cstddef>
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
	/* Dynamic page memory */
	MemoryBanks banks; // fault-in memory banks

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
	void fork_reset(vMemory& other, const MachineOptions&);
	static vMemory New(Machine&, const MachineOptions&, uint64_t phys, uint64_t safe, size_t size);

	/* Create new identity-mapped memory regions */
	vMemory(Machine&, const MachineOptions&, uint64_t, uint64_t, char*, size_t, bool = true);
	/* Loan memory from another machine */
	vMemory(Machine&, const MachineOptions&, const vMemory& other);
	~vMemory();
};

struct MemRange {
	uint64_t physbase;
	size_t   size;
	const char* name;

	auto begin() const noexcept { return physbase; }
	bool within(uint64_t addr, size_t asize = 1) const noexcept {
		return addr >= physbase && addr + asize <= physbase + this->size;
	}

	static MemRange New(const char*, uint64_t physical, size_t size);
};

}
