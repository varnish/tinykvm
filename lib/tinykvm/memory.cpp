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
	throw MemoryException("Memory::at() invalid region", addr, asize);
}
const uint64_t* vMemory::page_at(uint64_t addr) const
{
	if (within(addr, 4096))
		return (const uint64_t*) &ptr[addr - physbase];
	throw MemoryException("Memory::page_at() invalid region", addr, 4096);
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
#if 0
	// open a temporary file with owner privs
	int fd = memfd_create("tinykvm", 0);
	if (fd < 0) {
		throw std::runtime_error("Failed to open mkstemp file");
	}
	if (ftruncate(fd, size) < 0) {
		throw std::runtime_error("Failed to truncate memfd (Out of memory?)");
	}
#endif

	auto* ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (ptr == MAP_FAILED) {
		throw std::runtime_error("Failed to allocate guest memory");
	}
	madvise(ptr, size, MADV_MERGEABLE);
	return vMemory {
		.physbase = phys,
		.safebase = safe,
		.ptr  = ptr,
		.size = size,
		.fd   = -1
	};
}

vMemory vMemory::From(const vMemory& other, MemoryBanks& bank)
{
	char* ptr = bank.get(other.size);
	if (ptr == nullptr) {
		ptr = (char*) mmap(NULL, other.size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (ptr == MAP_FAILED) {
			throw std::runtime_error("Failed to map other machines guest memory");
		}
		madvise(ptr, other.size, MADV_MERGEABLE);
	}
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

void MemoryBanks::insert(char* ptr, std::size_t size)
{
	//madvise(ptr, size, MADV_FREE);
	std::lock_guard<std::mutex> lk(m_guard);
	m_mem.push_back({ptr, size});
}
char* MemoryBanks::get(std::size_t size)
{
	std::lock_guard<std::mutex> lk(m_guard);
	if (m_mem.empty()) return nullptr;
	auto result = m_mem.back();
	m_mem.pop_back();
	return result.ptr;
}

}
