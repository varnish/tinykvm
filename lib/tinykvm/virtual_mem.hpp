#pragma once
#include <cstdint>

namespace tinykvm {

struct VirtualMem {
	uint64_t physbase;
	char *   ptr;
	uint64_t size;

	VirtualMem(uint64_t phys, char* p, uint64_t s)
		: physbase(phys), ptr(p), size(s) {}

	static VirtualMem New(uint64_t physical, char* ptr, uint64_t size) {
		return VirtualMem { physical, ptr, size };
	}
};

}
