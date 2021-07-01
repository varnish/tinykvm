#pragma once
#include "common.hpp"
#include <cstddef>
#include <functional>
#include <string_view>
#include "memory_bank.hpp"

namespace tinykvm {
struct MemoryBanks;

struct vMemory {
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

	void reset();
	static vMemory New(uint64_t phys, uint64_t safe, size_t size);
	static vMemory From(uint64_t phys, char* ptr, size_t size);
	static vMemory From(const vMemory& other);
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
