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
void vMemory::fork_reset()
{
	banks.reset();
}

char* vMemory::at(uint64_t addr, size_t asize)
{
	if (within(addr, asize))
		return &ptr[addr - physbase];
	for (auto& bank : banks) {
		if (bank.within(addr, asize)) {
			return bank.at(addr);
		}
	}
	throw MemoryException("Memory::at() invalid region", addr, asize);
}
uint64_t* vMemory::page_at(uint64_t addr) const
{
	if (within(addr, PAGE_SIZE))
		return (uint64_t *)&ptr[addr - physbase];
	for (const auto& bank : banks) {
		if (bank.within(addr, PAGE_SIZE))
			return (uint64_t *)bank.at(addr);
	}
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
	/* XXX: Security checks */
	for (const auto& bank : banks) {
		if (bank.within(addr, asize)) {
			return bank.at(addr);
		}
	}
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

VirtualMem vMemory::vmem() const
{
	return VirtualMem::New(physbase, ptr, size);
}

MemoryBank::Page vMemory::new_page()
{
	return banks.get_available_bank().get_next_page();
}

char* vMemory::get_writable_page(uint64_t addr, bool zeroes)
{
//	printf("*** Need a writable page at 0x%lX  (%s)\n", addr, (zeroes) ? "zeroed" : "copy");
	char* ret = writable_page_at(*this, addr, zeroes);
//	printf("-> Translation of 0x%lX: 0x%lX\n",
//		addr, machine.translate(addr));
	//print_pagetables(*this);
	return ret;
}

}
