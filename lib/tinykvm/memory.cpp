#include "machine.hpp"
#include <cstring>
#include <sys/mman.h>
#include <stdexcept>
#include <string>
#include <unistd.h>

namespace tinykvm {

void vMemory::reset()
{
	std::memset(this->ptr, 0, this->size);
}

char* vMemory::at(uint64_t addr, size_t asize)
{
	if (within(addr, asize))
		return &ptr[addr - physbase];
	throw MemoryException("Memory::safely_at() invalid region", addr, asize);
}
char* vMemory::safely_at(uint64_t addr, size_t asize)
{
	if (safely_within(addr, asize))
		return &ptr[addr - physbase];
	throw MemoryException("Memory::safely_at() invalid region", addr, asize);
}
std::string_view vMemory::view(uint64_t addr, size_t asize) const {
	if (safely_within(addr, asize))
		return {&ptr[addr - physbase], asize};
	throw MemoryException("vMemory::view failed", addr, asize);
}

vMemory vMemory::New(uint64_t phys, uint64_t safe, size_t size)
{
	// open a temporary file with owner privs
	int fd = memfd_create("tinykvm", 0);
	if (fd < 0) {
		throw std::runtime_error("Failed to open mkstemp file");
	}
	if (ftruncate(fd, size) < 0) {
		throw std::runtime_error("Failed to truncate memfd (Out of memory?)");
	}

	auto* ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_SHARED | MAP_NORESERVE, fd, 0);
	if (ptr == MAP_FAILED) {
		throw std::runtime_error("Failed to allocate guest memory");
	}
	madvise(ptr, size, MADV_MERGEABLE);
	return vMemory {
		.physbase = phys,
		.safebase = safe,
		.ptr  = ptr,
		.size = size,
		.fd   = fd
	};
}

vMemory vMemory::From(const vMemory& other)
{
	auto* ptr = (char*) mmap(NULL, other.size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_NORESERVE, other.fd, 0);
	if (ptr == MAP_FAILED) {
		throw std::runtime_error("Failed to map other machines guest memory");
	}
	madvise(ptr, other.size, MADV_MERGEABLE);
	return vMemory {
		.physbase = other.physbase,
		.safebase = other.safebase,
		.ptr  = ptr,
		.size = other.size,
		.fd   = -1
	};
}

vMemory vMemory::From(uint64_t phys, char* ptr, size_t size)
{
	return vMemory {
		.physbase = phys,
		.safebase = phys,
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
