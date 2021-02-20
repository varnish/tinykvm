#include "machine.hpp"
#include <cstring>
#include <sys/mman.h>
#include <stdexcept>
#include <string>

namespace tinykvm {

void vMemory::reset()
{
	std::memset(this->ptr, 0, this->size);
}

char* vMemory::at(uint64_t addr)
{
	if (within(addr, 8))
		return &ptr[addr - physbase];
	throw std::runtime_error("Memory::at() invalid addr:size pair");
}

vMemory vMemory::New(uint64_t phys, uint64_t safe, size_t size)
{
	auto* ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (ptr == MAP_FAILED) {
		throw std::runtime_error("Failed to allocate guest memory");
	}
	madvise(ptr, size, MADV_MERGEABLE);
	return vMemory {
		.physbase = phys,
		.safebase = safe,
		.ptr  = ptr,
		.size = size
	};
}

MemRange MemRange::New(
	const char* name, uint64_t physbase, size_t size)
{
	return MemRange {
		.physbase = physbase,
		.size = size,
		.name = name
	};
}

}
