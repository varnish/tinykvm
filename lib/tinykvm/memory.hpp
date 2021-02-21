#pragma once
#include <cstddef>
#include <cstdint>
#include <string_view>

namespace tinykvm {

struct vMemory {
	uint64_t physbase;
	uint64_t safebase;
	char*  ptr;
	size_t size;

	/* Unsafe */
	bool within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= physbase) && (addr + asize <= physbase + this->size);
	}
	char* at(uint64_t addr);
	/* Safe */
	bool safely_within(uint64_t addr, size_t asize) const noexcept {
		return (addr >= safebase) && (addr + asize <= physbase + this->size);
	}
	char* safely_at(uint64_t addr, size_t asize);
	std::string_view view(uint64_t addr, size_t asize) const noexcept {
		if (safely_within(addr, asize))
			return {&ptr[addr - physbase], asize};
		return {};
	}

	void reset();
	static vMemory New(uint64_t, uint64_t, size_t size);
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
