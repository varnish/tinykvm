#include "machine.hpp"
#include <cstring>
#include <sys/mman.h>
#include <string>
#include <unistd.h>
#include "kernel/amd64.hpp"
#include "kernel/paging.hpp"
#include "kernel/memory_layout.hpp"

#define ALT_ARENA      0xC000000000
#define ALT_ARENA_SIZE 0x4000000000
#define ALT_ARENA_END  (ALT_ARENA + ALT_ARENA_SIZE)
#define ALT_ARENA_PHYS 0x8000000
#define KERNEL_BOUNDARY  0x40000

namespace tinykvm {

static bool page_is_zeroed(uint64_t* page) {
	for (size_t i = 0; i < 512; i += 8) {
		if ((page[i+0] | page[i+1] | page[i+2] | page[i+3]) != 0 ||
			(page[i+4] | page[i+5] | page[i+6] | page[i+7]) != 0)
			return false;
	}
	return true;
}

vMemory::vMemory(Machine& m, const MachineOptions& options,
	uint64_t ph, uint64_t sf, char* p, size_t s, bool own)
	: machine(m), physbase(ph), safebase(sf),
	  ptr(p), size(s), owned(own),
	  banks(m, options)
{
	this->page_tables = PT_ADDR;
}
vMemory::vMemory(Machine& m, const MachineOptions& options, const vMemory& other)
	: vMemory{m, options, other.physbase, other.safebase, other.ptr, other.size, false}
{
	if (UNLIKELY(options.linearize_memory))
	{
		// Allocate new memory for this VM, own it
		this->ptr = (char*)mmap(NULL, this->size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (ptr == MAP_FAILED) {
			memory_exception("Failed to allocate guest memory", 0, this->size);
		}
		madvise(ptr, size, MADV_MERGEABLE);
		this->owned = true;
		// Copy the entire memory from the original VM (expensive!)
		// XXX: Brutally slow. TODO: Change for MAP_SHARED!!!
		for (uint64_t off = 0; off < other.size; off += PAGE_SIZE) {
			uint64_t* other_page = (uint64_t*)&other.ptr[off];
			if (!page_is_zeroed(other_page)) {
				std::memcpy(&ptr[off], other_page, PAGE_SIZE);
			}
		}
		// For each active bank page, commit it to master memory
		// then clear out all the memory banks.
		for (const auto& bank : other.banks) {
			for (size_t i = 0; i < bank.n_used; i++) {
				const uint64_t vaddr = bank.page_vaddr.at(i);
				// Pages "at" zero are pagetable pages, and we don't want
				// those anymore as we are sequentializing memory.
				if (vaddr >= KERNEL_BOUNDARY && within(vaddr, PAGE_SIZE)) {
					std::memcpy(&ptr[vaddr], &bank.mem[i * PAGE_SIZE], PAGE_SIZE);
				} else {
					/*char buffer[128];
					const int len = snprintf(buffer, sizeof(buffer),
						"WARNING: Skipped page 0x%lX\n", vaddr);
					m.print(buffer, len);*/
				}
			}
		}
	}
}
vMemory::~vMemory()
{
	if (this->owned) {
		munmap(this->ptr, this->size);
	}
}

void vMemory::fork_reset(const MachineOptions& options)
{
	banks.reset(options);
}
void vMemory::fork_reset(vMemory& other, const MachineOptions& options)
{
	this->physbase = other.physbase;
	this->safebase = other.safebase;
	this->owned    = false;
	this->ptr  = other.ptr;
	this->size = other.size;
	banks.reset(options);
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
	if (is_alt_arena(addr, asize)) {
		return at(arena_transform(addr), asize);
	}
	memory_exception("Memory::at() invalid region", addr, asize);
}
uint64_t* vMemory::page_at(uint64_t addr) const
{
	if (within(addr, PAGE_SIZE))
		return (uint64_t *)&ptr[addr - physbase];
	for (const auto& bank : banks) {
		if (bank.within(addr, PAGE_SIZE))
			return (uint64_t *)bank.at(addr);
	}
	memory_exception("Memory::page_at() invalid region", addr, 4096);
}
char* vMemory::safely_at(uint64_t addr, size_t asize)
{
	if (safely_within(addr, asize))
		return &ptr[addr - physbase];
	/* XXX: Security checks */
	for (auto& bank : banks) {
		if (bank.within(addr, asize)) {
			return bank.at(addr);
		}
	}
	if (is_alt_arena(addr, asize)) {
		return safely_at(arena_transform(addr), asize);
	}
	memory_exception("Memory::safely_at() invalid region", addr, asize);
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
	if (is_alt_arena(addr, asize)) {
		return view(arena_transform(addr), asize);
	}
	memory_exception("vMemory::view failed", addr, asize);
}

bool vMemory::is_alt_arena(uint64_t addr, uint64_t asize) const noexcept {
	return addr >= ALT_ARENA && addr + asize < ALT_ARENA_END;
}
uint64_t vMemory::arena_transform(uint64_t addr) const noexcept {
	uint64_t offset = addr - ALT_ARENA;
	return ALT_ARENA_PHYS + offset;
}


vMemory vMemory::New(Machine& m, const MachineOptions& options,
	uint64_t phys, uint64_t safe, size_t size)
{
#if 0
	// open a temporary file with owner privs
	int fd = memfd_create("tinykvm", 0);
	if (fd < 0) {
		memory_exception("Failed to open mkstemp file", 0, 0);
	}
	if (ftruncate(fd, size) < 0) {
		memory_exception("Failed to truncate memfd (Out of memory?)", 0, size);
	}
#endif

	auto* ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
		MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (ptr == MAP_FAILED) {
		memory_exception("Failed to allocate guest memory", 0, size);
	}
	madvise(ptr, size, MADV_MERGEABLE);
	return vMemory(m, options, phys, safe, ptr, size);
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

MemoryBank::Page vMemory::new_page(uint64_t vaddr)
{
	return banks.get_available_bank().get_next_page(vaddr);
}

char* vMemory::get_writable_page(uint64_t addr, bool zeroes)
{
//	printf("*** Need a writable page at 0x%lX  (%s)\n", addr, (zeroes) ? "zeroed" : "copy");
	char* ret = writable_page_at(*this, addr, zeroes);
	//printf("-> Translation of 0x%lX: 0x%lX\n",
	//	addr, machine.translate(addr));
	//print_pagetables(*this);
	return ret;
}

char* vMemory::get_kernelpage_at(uint64_t addr)
{
	constexpr uint64_t flags = PDE64_PRESENT;
	return readable_page_at(*this, addr, flags);
}

char* vMemory::get_userpage_at(uint64_t addr)
{
	constexpr uint64_t flags = PDE64_PRESENT | PDE64_USER;
	return readable_page_at(*this, addr, flags);
}

__attribute__((cold, noreturn))
void vMemory::memory_exception(const char* msg, uint64_t addr, uint64_t size)
{
	throw MemoryException(msg, addr, size);
}

}
