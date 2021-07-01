#include "machine.hpp"
#include <cstring>
#include <sys/mman.h>
#include <string>
#include <unistd.h>
#include "kernel/amd64.hpp"
#include "kernel/paging.hpp"
#include "kernel/memory_layout.hpp"

namespace tinykvm {

vMemory::vMemory(Machine& m, uint64_t ph, uint64_t sf, char* p, size_t s, bool own)
	: machine(m), physbase(ph), safebase(sf),
	  ptr(p), size(s), owned(own),
	  banks(m)
{
	this->page_tables = PT_ADDR;
}

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
uint64_t* vMemory::page_at(uint64_t addr) const
{
	if (within(addr, 4096))
		return (uint64_t*) &ptr[addr - physbase];
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

vMemory vMemory::New(Machine& m, uint64_t phys, uint64_t safe, size_t size)
{
#if 0
	// open a temporary file with owner privs
	int fd = memfd_create("tinykvm", 0);
	if (fd < 0) {
		throw MemoryException("Failed to open mkstemp file", 0, 0);
	}
	if (ftruncate(fd, size) < 0) {
		throw MemoryException("Failed to truncate memfd (Out of memory?)", 0, size);
	}
#endif

	auto* ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (ptr == MAP_FAILED) {
		throw MemoryException("Failed to allocate guest memory", 0, size);
	}
	madvise(ptr, size, MADV_MERGEABLE);
	return vMemory(m, phys, safe, ptr, size);
}

vMemory vMemory::From(Machine& m, const vMemory& other)
{
	return vMemory(m, other.physbase, other.safebase, other.ptr, other.size, false);
}

vMemory vMemory::From(Machine& m, uint64_t phys, char* ptr, size_t size)
{
	return vMemory(m, phys, phys, ptr, size);
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

MemoryBank::Page vMemory::new_page()
{
	return banks.get_available_bank().get_next_page();
}

char* vMemory::get_writable_page(uint64_t addr)
{
	/** TODO:
	 * 1. Check if page is already forked
	 **/
	bool needs_replacement = false;
	tinykvm::page_at(*this, addr,
		[&needs_replacement] (uint64_t addr, uint64_t& entry, uint64_t size) {
			if ((entry & PDE64_PRESENT) == 0)
				throw MemoryException("get_writable_page(): page not present", addr, size);
			needs_replacement = !(entry & (1 << 9));
		});
	/**
	 * 2. Allocate memory bank page
	 * 3. Get memory bank page physical address
	 * 4. Recursively copy page tables
	 * 5. Mark final entry as user-read-write-present
	 **/
	return nullptr;
}

}
