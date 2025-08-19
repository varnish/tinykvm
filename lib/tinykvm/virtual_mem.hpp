#pragma once
#include <cstdint>

namespace tinykvm {

struct VirtualMem {
	uint64_t physbase;
	char *   ptr;
	uint64_t virtbase = 0;
	uint64_t size;

	VirtualMem(uint64_t phys, char* p, uint64_t s)
		: physbase(phys), ptr(p), size(s) {}

	VirtualMem(uint64_t phys, char* p, uint64_t v, uint64_t s)
		: physbase(phys), ptr(p), virtbase(v), size(s) {}

	static VirtualMem New(uint64_t physical, char* ptr, uint64_t size) {
		return VirtualMem { physical, ptr, size };
	}

	bool overlaps(uint64_t vbase, uint64_t vsize) const {
		if (vbase + vsize <= virtbase || virtbase + size <= vbase) {
			return false; // No overlap
		}
		return (virtbase <= vbase + vsize) && (vbase <= virtbase + size);
	}
};

}
