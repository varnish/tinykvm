#include "machine.hpp"
#include <cstring>
#include <sys/mman.h>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include "page_streaming.hpp"
#include "kernel/amd64.hpp"
#include "kernel/paging.hpp"
#include "kernel/memory_layout.hpp"

namespace tinykvm {

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
		const auto [res_ptr, res_size] = allocate_mapped_memory(options, this->size);
		this->owned = true;
		this->ptr  = res_ptr;
		this->size = res_size;

		const uint64_t kernel_end = other.machine.kernel_end_address();
		const uint64_t mmap_end   = other.machine.mmap();
		const uint64_t memory_end = std::min(other.size, mmap_end);
		const uint64_t stack_base = other.machine.stack_address() & ~(uint64_t)0xFFF;
		/*printf("Kernel end is 0x%lX. Memory end is 0x%lX vs mmap end: 0x%lX\n"
			"Stack base: 0x%lX\n",
			kernel_end, other.size, mmap_end,
			stack_base);*/
		std::unordered_set<uint64_t> already_duplicated;

		// For each active bank page, commit it to master memory
		// then clear out all the memory banks.
		for (const auto& bank : other.banks) {
			for (size_t i = 0; i < bank.n_used; i++) {
				const uint64_t vaddr = bank.page_vaddr.at(i);
				// Pages "at" zero are pagetable pages, and we don't want
				// those anymore as we are sequentializing memory.
				// Also, the stack is below the program itself, so we can
				// just ignore everything below that point.
				if (vaddr >= stack_base && within(vaddr, PAGE_SIZE)) {
					avx2_page_dupliteit(
						(uint64_t*)&ptr[vaddr], (uint64_t*)&bank.mem[i * PAGE_SIZE]);
					already_duplicated.insert(vaddr);
				} else {
					//printf("WARNING: Skipped page 0x%lX\n", vaddr);
				}
			}
		}
		// Copy the entire memory from the original VM (expensive!)
		/* NOTE to self: Don't use permission- or pagetable-based
		   page getters here. This is how it's supposed to work. */
		for (uint64_t off = 0x1000; off < kernel_end; off += PAGE_SIZE) {
			const auto* other_page = other.page_at(off);
			avx2_page_dupliteit((uint64_t*)&ptr[off], other_page);
		}
		for (uint64_t off = stack_base; off < memory_end; off += PAGE_SIZE) {
			const auto* other_page = other.page_at(off);
			if (already_duplicated.count(off) == 0)
				avx2_page_dupliteit((uint64_t*)&ptr[off], other_page);
		}
	}
}
vMemory::~vMemory()
{
	if (this->owned) {
		munmap(this->ptr, this->size);
	}
}

bool vMemory::compare(const vMemory& other)
{
	return this->ptr == other.ptr;
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
	memory_exception("Memory::at() invalid region", addr, asize);
}
const char* vMemory::at(uint64_t addr, size_t asize) const
{
	if (within(addr, asize))
		return &ptr[addr - physbase];
	for (auto& bank : banks) {
		if (bank.within(addr, asize)) {
			return bank.at(addr);
		}
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
	memory_exception("vMemory::view failed", addr, asize);
}

vMemory::AllocationResult vMemory::allocate_mapped_memory(
	const MachineOptions& options, size_t size)
{
	char* ptr = (char*) MAP_FAILED;
	if (options.hugepages) {
		size &= ~0x200000L;
		if (size < 0x200000L) {
			memory_exception("Not enough guest memory", 0, size);
		}
		// Try 2MB pages first
		ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_HUGETLB, -1, 0);
	} else {
		// Only 4KB pages
		if (size < 0x1000L) {
			memory_exception("Not enough guest memory", 0, size);
		}
	}
	if (ptr == MAP_FAILED) {
		// Try again without 2MB pages
		ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
		if (ptr == MAP_FAILED) {
			memory_exception("Failed to allocate guest memory", 0, size);
		}
	}
	int advice = 0x0;
	if (!options.short_lived) {
		advice |= MADV_MERGEABLE;
	}
	if (options.transparent_hugepages) {
		advice |= MADV_HUGEPAGE;
	}
	if (advice != 0x0) {
		madvise(ptr, size, advice);
	}
	return AllocationResult{ptr, size};
}

vMemory vMemory::New(Machine& m, const MachineOptions& options,
	uint64_t phys, uint64_t safe, size_t size)
{
	const auto [res_ptr, res_size] = allocate_mapped_memory(options, size);
	return vMemory(m, options, phys, safe, res_ptr, res_size);
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
	std::lock_guard<std::mutex> lock (this->mtx_smp);
//	printf("*** Need a writable page at 0x%lX  (%s)\n", addr, (zeroes) ? "zeroed" : "copy");
	char* ret = writable_page_at(*this, addr, zeroes);
	//printf("-> Translation of 0x%lX: 0x%lX\n",
	//	addr, machine.translate(addr));
	//print_pagetables(*this);
	return ret;
}

char* vMemory::get_kernelpage_at(uint64_t addr) const
{
	constexpr uint64_t flags = PDE64_PRESENT;
	return readable_page_at(*this, addr, flags);
}

char* vMemory::get_userpage_at(uint64_t addr) const
{
	constexpr uint64_t flags = PDE64_PRESENT | PDE64_USER;
	return readable_page_at(*this, addr, flags);
}

size_t Machine::banked_memory_pages() const noexcept
{
	size_t count = 0;
	for (const auto& bank : memory.banks) {
		count += bank.n_used;
	}
	return count;
}
size_t Machine::banked_memory_capacity_pages() const noexcept
{
	size_t count = 0;
	for (const auto& bank : memory.banks) {
		count += bank.n_pages;
	}
	return count;
}

__attribute__((cold, noreturn))
void vMemory::memory_exception(const char* msg, uint64_t addr, uint64_t size)
{
	throw MemoryException(msg, addr, size);
}

}
