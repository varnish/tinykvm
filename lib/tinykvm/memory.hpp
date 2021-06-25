#pragma once
#include "common.hpp"
#include <cstddef>
#include <string_view>

namespace tinykvm {
struct MemoryBanks;

struct vMemory {
	uint64_t physbase;
	uint64_t safebase;
	char*  ptr;
	size_t size;
	bool   owned = true;

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
	static vMemory From(const vMemory& other, MemoryBanks& bank);
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
