#pragma once
#include "common.hpp"
#include "memory_bank.hpp"
#include "virtual_mem.hpp"
#include <cstddef>
#include <functional>
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
	std::function<void(int)> install_memory_at;

	/* Unsafe */
	bool within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= physbase) && (addr + asize <= physbase + this->size);
	}
	char* at(uint64_t addr, size_t asize = 8);
	uint64_t* page_at(uint64_t addr) const;
	/* Safe */
	bool safely_within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= safebase) && (addr + asize <= physbase + this->size);
	}
	char* safely_at(uint64_t addr, size_t asize);
	std::string_view view(uint64_t addr, size_t asize) const;

	char *get_writable_page(uint64_t addr);
	MemoryBank::Page new_page();

	VirtualMem vmem() const;

	void reset();
	void fork_reset();
	static vMemory New(Machine&, uint64_t phys, uint64_t safe, size_t size);
	static vMemory From(Machine&, uint64_t phys, char* ptr, size_t size);
	static vMemory From(Machine&, const vMemory& other);

	vMemory(Machine&, uint64_t, uint64_t, char*, size_t, bool = true);
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
