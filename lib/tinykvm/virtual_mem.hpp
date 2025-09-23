#pragma once
#include <cstdint>

namespace tinykvm {

struct VirtualMem {
	uint64_t physbase;
	char *   ptr;
	uint64_t virtbase = 0;
	uint64_t size;
	uint64_t remote_end = 0; // End of remote vmem (for remote calls)
	unsigned bank_idx = 0; // Optional bank index
	std::string filename; // Optional, for file-backed mappings

	VirtualMem(uint64_t phys, char* p, uint64_t s, uint64_t vb = 0, uint64_t r = 0)
		: physbase(phys), ptr(p), virtbase(vb), size(s), remote_end(r) {}

	VirtualMem(uint64_t phys, char* p, uint64_t v, uint64_t s, std::string f = "")
		: physbase(phys), ptr(p), virtbase(v), size(s), filename(std::move(f)) {}

	static VirtualMem New(uint64_t physical, char* ptr, uint64_t size, uint64_t remote_end = 0) {
		return VirtualMem { physical, ptr, size, 0, remote_end };
	}

	bool overlaps(uint64_t vbase, uint64_t vsize) const {
		if (vbase + vsize <= virtbase || virtbase + size <= vbase) {
			return false; // No overlap
		}
		return (virtbase <= vbase + vsize) && (vbase <= virtbase + size);
	}
	bool overlaps_physical(uint64_t pbase, uint64_t psize) const {
		if (pbase + psize <= physbase || physbase + size <= pbase) {
			return false; // No overlap
		}
		return (physbase <= pbase + psize) && (pbase <= physbase + size);
	}
};

}
