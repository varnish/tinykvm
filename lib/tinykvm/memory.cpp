#include "machine.hpp"
#include <algorithm>
#include <cstring>
#include <sys/mman.h>
#include <stdexcept>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include "page_streaming.hpp"
#ifdef TINYKVM_ARCH_AMD64
#include "amd64/amd64.hpp"
#include "amd64/memory_layout.hpp"
#include "amd64/paging.hpp"
#else
#include "arm64/memory_layout.hpp"
#endif

namespace tinykvm {
#define USERMODE_FLAGS (0x7 | 1UL << 63) /* USER, READ/WRITE, PRESENT, NX */

vMemory::vMemory(Machine& m, const MachineOptions& options,
	uint64_t ph, uint64_t sf, char* p, size_t s, bool own)
	: machine(m), physbase(ph), safebase(sf),
	  // Over-allocate in order to avoid trouble with 2MB-aligned operations
	  ptr(p), size(overaligned_memsize(s)), owned(own),
	  main_memory_writes(options.master_direct_memory_writes),
	  split_hugepages(options.split_hugepages),
	  executable_heap(options.executable_heap),
	  banks(m, options)
{
	// Main memory is not always starting at 0x0
	// The default top-level pagetable location
	this->page_tables = this->physbase + PT_ADDR;
}
vMemory::vMemory(Machine& m, const MachineOptions& options, const vMemory& other)
	: vMemory{m, options, other.physbase, other.safebase, other.ptr, other.size, false}
{
	this->executable_heap = other.executable_heap;
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

void vMemory::record_cow_page(uint64_t addr, uint64_t entry)
{
	// If the page is writable, we will restore the original
	// memory from the master VM. We only care about leaf pages.
	if (machine.is_forked() && entry & PDE64_USER) {
		auto it = std::lower_bound(cow_written_pages.begin(), cow_written_pages.end(), addr);
		cow_written_pages.insert(it, addr);
	}
}

bool vMemory::fork_reset(const Machine& main_vm, const MachineOptions& options)
{
	if (options.reset_keep_all_work_memory) {
		// With this method, instead of resetting the memory banks,
		// and the pagetables, which requires an expensive mov cr3,
		// we will iterate the pagetables and copy non-CoW pages
		// from the master VM to this forked VM. This is a gamble
		// that it's cheaper to copy than the TLB flushes that happen
		// from the mov cr3.
		if (options.reset_free_work_mem != 0) {
			// When reset_free_work_mem is non-zero, we will compare the
			// memory bank working memory usage against the limit.
			// If the limit is exceeded, we will return true to indicate
			// that a full reset is to be performed, which will release
			// memory back to the system, keeping memory usage in check.
			const uint64_t used = this->machine.banked_memory_pages() *
				vMemory::PageSize();
			if (used > uint64_t(options.reset_free_work_mem)) {
				//fprintf(stderr, "Freeing %zu bytes of work memory\n", used);
				this->banks.reset(options);
				cow_written_pages.clear();
				return true;
			}
		}
		try {
		for (const uint64_t addr : cow_written_pages) {
			tinykvm::page_at(*this, addr, [&](uint64_t addr, uint64_t& entry, uint64_t page_size) {
#define PDE64_CLONEABLE  (1ul << 11)
				static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
				const uint64_t bank_addr = entry & PDE64_ADDR_MASK;
				//fprintf(stderr, "Copying virtual page %016lx from physical %016lx with size %lu\n",
				//	addr, bank_addr, page_size);

				// This is a writable page, we will copy it using the "real"
				// address from the master VM.
				auto* our_page = this->safely_at(bank_addr, page_size);
				// Find the page in the main VM
				bool duplicate = true;
				tinykvm::page_at(const_cast<vMemory&> (main_vm.main_memory()), addr,
					[&](uint64_t, uint64_t& entry, size_t) {
						if ((entry & PDE64_DIRTY) == 0) {
							madvise(our_page, page_size, MADV_DONTNEED);
							duplicate = false;
						}
					});
				if (duplicate) {
					page_duplicate((uint64_t*)our_page,
						(const uint64_t*)main_vm.main_memory().safely_at(addr, page_size));
					//entry |= PDE64_CLONEABLE;
					//entry &= ~(PDE64_PRESENT | PDE64_RW);
				}
			}, false);
		}
		return false;
		} catch (const std::exception& e) {
			/// XXX: Silently ignore the exception, as we will just completely reset the memory banks
			//fprintf(stderr, "Failed to copy memory from master VM: %s\n", e.what());
		}
		/// Fallthrough to reset the memory banks
	}
	// Reset the memory banks (also fallback if the above fails)
	banks.reset(options);
	cow_written_pages.clear();
	return true;
}
void vMemory::fork_reset(const vMemory& other, const MachineOptions& options)
{
	this->physbase = other.physbase;
	this->safebase = other.safebase;
	this->owned    = false;
	this->ptr  = other.ptr;
	this->size = other.size;
	banks.reset(options);
}
bool vMemory::is_forkable_master() const noexcept
{
	return machine.is_forkable();
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
	/* Remote machine always last resort */
	if (machine.is_remote_connected())
	{
		return machine.remote().main_memory().page_at(addr);
	}
	memory_exception("Memory::page_at() invalid region", addr, 4096);
}
char* vMemory::safely_at(uint64_t addr, size_t asize)
{
	/* XXX: Security checks */
	for (auto& bank : banks) {
		if (bank.within(addr, asize)) {
			return bank.at(addr);
		}
	}

	if (safely_within(addr, asize))
		return &ptr[addr - physbase];
	/* Remote machine always last resort */
	if (machine.is_remote_connected())
	{
		return machine.remote().main_memory().safely_at(addr, asize);
	}

	/* Slow-path page walk */
	const auto pagebase = addr & ~PageMask();
	const auto offset   = addr & PageMask();
	if (offset + asize <= vMemory::PageSize())
	{
		auto* page = this->get_writable_page(pagebase, expectedUsermodeFlags(), false);
		return &page[offset];
	}

	memory_exception("Memory::safely_at() invalid region", addr, asize);
}
const char* vMemory::safely_at(uint64_t addr, size_t asize) const
{
	if (safely_within(addr, asize))
		return &ptr[addr - physbase];
	/* XXX: Security checks */
	for (auto& bank : banks) {
		if (bank.within(addr, asize)) {
			return bank.at(addr);
		}
	}
	/* Remote machine always last resort */
	if (machine.is_remote_connected())
	{
		return machine.remote().main_memory().safely_at(addr, asize);
	}

	/* Slow-path page walk */
	const auto pagebase = addr & ~PageMask();
	const auto offset   = addr & PageMask();
	if (offset + asize <= vMemory::PageSize())
	{
		auto* page = this->get_userpage_at(pagebase);
		return &page[offset];
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
	/* Remote machine always last resort */
	if (machine.is_remote_connected())
	{
		return machine.remote().main_memory().view(addr, asize);
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
		if (options.hugepages_arena_size != 0) {
			// 1. Allocate 4k pages for the entire arena
			ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
			if (ptr == MAP_FAILED) {
				memory_exception("Failed to allocate guest memory", 0, size);
			}
			// 2. Try to allocate 2MB pages over the beginning of the arena
			//    (this will fail if the arena is not aligned to 2MB)
			munmap(ptr, options.hugepages_arena_size);
			char* hugeptr = (char*) mmap(ptr, options.hugepages_arena_size, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_HUGETLB, -1, 0);
			if (hugeptr == MAP_FAILED) {
				// This might fail, but we can still use the 4k pages
				//printf("Failed to allocate hugepages over arena: %s\n", strerror(errno));
				fprintf(stderr, "Failed to allocate hugepages over arena\n");
				/// XXX: Redo the mmap with 4k pages?
				mmap(ptr, options.hugepages_arena_size, PROT_READ | PROT_WRITE,
					MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
			}
		} else {
			// Try 2MB pages first
			ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
				MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE | MAP_HUGETLB, -1, 0);
		}
	} else {
		// Only 4KB pages
		if (size < 0x1000L) {
			memory_exception("Not enough guest memory", 0, size);
		}
	}
	if (ptr == MAP_FAILED) {
		// Try again with 4k pages
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
	if (UNLIKELY(phys & 0xFFFFF))
		throw MachineException("Invalid physical memory alignment. Must be at least 2MB aligned.", phys);
	// Over-allocate in order to avoid trouble with 2MB-aligned operations
	size = vMemory::overaligned_memsize(size);
	const auto [res_ptr, res_size] = allocate_mapped_memory(options, size);
	return vMemory(m, options, phys, safe, res_ptr, res_size);
}

VirtualMem vMemory::vmem() const
{
	return VirtualMem::New(physbase, ptr, size);
}

MemoryBank::Page vMemory::new_page()
{
	return banks.get_available_bank(1u).get_next_page(1u);
}
MemoryBank::Page vMemory::new_hugepage()
{
	return banks.get_available_bank(512u).get_next_page(512u);
}

char* vMemory::get_writable_page(uint64_t addr, uint64_t flags, bool zeroes)
{
//	printf("*** Need a writable page at 0x%lX  (%s)\n", addr, (zeroes) ? "zeroed" : "copy");
	if (LIKELY(this->smp_guards_enabled == false))
		return writable_page_at(*this, addr, flags, zeroes);

	std::lock_guard<std::mutex> lock (this->mtx_smp);
	char* ret = writable_page_at(*this, addr, flags, zeroes);
	//printf("-> Translation of 0x%lX: 0x%lX\n",
	//	addr, machine.translate(addr));
	//print_pagetables(*this);
	return ret;
}

char* vMemory::get_kernelpage_at(uint64_t addr) const
{
#ifdef TINYKVM_ARCH_AMD64
	constexpr uint64_t flags = PDE64_PRESENT;
	return readable_page_at(*this, addr, flags);
#else
#error "Implement me!"
#endif
}

char* vMemory::get_userpage_at(uint64_t addr) const
{
#ifdef TINYKVM_ARCH_AMD64
	constexpr uint64_t flags = PDE64_PRESENT | PDE64_USER;
	return readable_page_at(*this, addr, flags);
#else
#error "Implement me!"
#endif
}

size_t Machine::banked_memory_pages() const noexcept
{
	size_t count = 0;
	for (const auto& bank : memory.banks) {
		count += bank.n_used;
	}
	return count;
}
size_t Machine::banked_memory_allocated_pages() const noexcept
{
	size_t count = 0;
	for (const auto& bank : memory.banks) {
		count += bank.n_pages;
	}
	return count;
}
size_t Machine::banked_memory_capacity_pages() const noexcept
{
	return memory.banks.max_pages();
}

__attribute__((cold, noreturn))
void vMemory::memory_exception(const char* msg, uint64_t addr, uint64_t size)
{
	throw MemoryException(msg, addr, size);
}

void vMemory::increment_unlocked_pages(size_t pages)
{
	if (this->main_memory_writes) {
		this->unlocked_pages += pages;
		if (this->unlocked_pages > this->banks.max_pages()) {
			memory_exception("Out of working memory",
				this->unlocked_pages * PAGE_SIZE, this->banks.max_pages() * PAGE_SIZE);
		}
	} else {
		memory_exception("Memory::increment_unlocked_pages() without direct main memory writes enabled", 0, pages);
	}
}

uint64_t vMemory::expectedUsermodeFlags() const noexcept
{
	uint64_t flags = PDE64_PRESENT | PDE64_USER | PDE64_RW;
	if (!this->executable_heap)
		flags |= PDE64_NX;
	return flags;
}

} // namespace tinykvm
