#include "machine.hpp"
#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
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
static constexpr bool VERBOSE_MMAP = false;

vMemory::vMemory(Machine& m, const MachineOptions& options,
	uint64_t ph, uint64_t sf, char* p, size_t s, int fd, bool own)
	: machine(m), physbase(ph), safebase(sf),
	  // Over-allocate in order to avoid trouble with 2MB-aligned operations
	  ptr(p), size(overaligned_memsize(s)),
	  owned(own), snapshot_fd(fd),
	  main_memory_writes(options.master_direct_memory_writes),
	  split_hugepages(options.split_hugepages),
	  executable_heap(options.executable_heap),
	  mmap_backed_files(options.mmap_backed_files),
	  banks(m, options)
{
	// Main memory is not always starting at 0x0
	// The default top-level pagetable location
	this->page_tables = this->physbase + PT_ADDR;
	// Find the end of the virtual memory space, which includes
	// any remapped areas. Remote access uses this to determine
	// whether an address is inside this VM's memory space.
	this->remote_end = this->physbase + this->size;
	for (const auto& mapping : options.remappings) {
		if (mapping.blackout) {
			continue;
		}
		this->remote_end = std::max(this->remote_end, mapping.virt + mapping.size);
	}

	this->mmap_physical = MMAP_PHYS_BASE + ((physbase == 0) ? 0x0 : 0x2000000000);
	this->mmap_physical_begin = this->mmap_physical;
	if constexpr (VERBOSE_MMAP) {
		fprintf(stderr, "vMemory: physbase=0x%lX safebase=0x%lX size=0x%zX mmap_physical=0x%lX bank_physical=0x%lX\n",
			physbase, safebase, size, mmap_physical_begin, banks.arena_begin());
	}
}
vMemory::vMemory(Machine& m, const MachineOptions& options, const vMemory& other)
	: vMemory{m, options, other.physbase, other.safebase, other.ptr, other.size, -1, false}
{
	this->executable_heap = other.executable_heap;
	this->mmap_physical_begin = other.mmap_physical_begin;
	this->mmap_physical = other.mmap_physical;
	this->remote_end = other.remote_end;
	banks.init_from(other.banks);
}
vMemory::~vMemory()
{
	if (this->owned) {
		munmap(this->ptr, this->size);

		for (auto& mmap_files : this->mmap_ranges) {
			if (mmap_files.ptr != nullptr) {
				munmap(mmap_files.ptr, mmap_files.size);
			}
		}
	}
}
unsigned vMemory::allocate_region_idx()
{
	if (!m_bank_idx_free_list.empty()) {
		// Reuse a previously freed index
		auto idx = m_bank_idx_free_list.back();
		m_bank_idx_free_list.pop_back();
		return idx;
	}
	// Allocate a new index
	return banks.allocate_region_idx();
}
void vMemory::install_mmap_ranges(const Machine &other)
{
	for (auto& range : other.main_memory().mmap_ranges)
	{
		for (const auto& existing : this->mmap_ranges) {
			if (existing.overlaps_physical(range.physbase, range.size)) {
				// Already installed
				if constexpr (VERBOSE_MMAP) {
					printf("Error: overlapping mmap ranges detected at 0x%lX-0x%lX of size %zu KiB file %s\n",
						range.physbase, range.physbase + range.size, range.size >> 10, range.filename.c_str());
					printf("  Existing range at 0x%lX-0x%lX file %s\n",
						existing.physbase, existing.physbase + existing.size, existing.filename.c_str());
				}
				throw std::runtime_error("Overlapping mmap ranges detected");
			}
		}
		if constexpr (VERBOSE_MMAP) {
			printf("Installing mmap range at 0x%lX of size %zu KiB file %s\n",
				range.physbase, range.size >> 10, range.filename.c_str());
		}
		// Install the mmap range in a new memory slot
		const unsigned region_idx = this->allocate_region_idx();
		machine.install_memory(region_idx, range, false);
		// Record the mmap range
		auto new_range = range;
		new_range.bank_idx = region_idx;
		this->mmap_ranges.push_back(new_range);
	}
}
void vMemory::delete_foreign_mmap_ranges()
{
	for (auto it = this->mmap_ranges.begin(); it != this->mmap_ranges.end(); ){
		// Only delete ranges that are not part of this VM's memory
		const auto& range = *it;
		if (range.physbase >= this->mmap_physical || range.physbase < this->mmap_physical_begin) {
			machine.delete_memory(range.bank_idx);
			this->m_bank_idx_free_list.push_back(range.bank_idx);
			if constexpr (VERBOSE_MMAP) {
				printf("Removed foreign mmap range at 0x%lX of size %zu KiB file %s\n",
					range.physbase, range.size >> 10, range.filename.c_str());
			}
			it = this->mmap_ranges.erase(it);
		} else {
			++it;
		}
	}
}
void vMemory::delete_foreign_banks()
{
	for (auto slot_idx : this->foreign_banks) {
		machine.delete_memory(slot_idx);
		this->m_bank_idx_free_list.push_back(slot_idx);
		if constexpr (VERBOSE_MMAP) {
			printf("Removed foreign memory bank at slot %u\n", slot_idx);
		}
	}
	this->foreign_banks.clear();
}

bool vMemory::compare(const vMemory& other)
{
	return this->ptr == other.ptr;
}

void vMemory::record_cow_leaf_user_page(uint64_t addr)
{
	// When running forked, record page address to be restored in fork_reset.
	// Pages are assumed to be leaf user pages.
	if (machine.is_forked()) {
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
		// Restore the original memory from the master VM.
		try {
		for (const uint64_t addr : cow_written_pages) {
			tinykvm::page_at(*this, addr, [&](uint64_t addr, uint64_t& entry, uint64_t page_size) {
				static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
				const uint64_t bank_addr = entry & PDE64_ADDR_MASK;
				//fprintf(stderr, "Copying virtual page %016lx from physical %016lx with size %lu\n",
				//	addr, bank_addr, page_size);

				// This is a writable page, we will copy it using the "real"
				// address from the master VM.
				auto* our_page = this->safely_at(bank_addr, page_size);
				// Find the page in the main VM
				page_duplicate((uint64_t*)our_page,
					(const uint64_t*)main_vm.main_memory().safely_at(addr, page_size));
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
	/* mmap ranges */
	for (const auto& vmem : mmap_ranges) {
		if (addr >= vmem.physbase && addr < vmem.physbase + vmem.size) {
			return (uint64_t *)(vmem.ptr + (addr - vmem.physbase));
		}
	}
	/* Remote machine always last resort */
	if (machine.has_remote()) {
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
	if (machine.has_remote()) {
		return machine.remote().main_memory().safely_at(addr, asize);
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
	if (machine.has_remote()) {
		return machine.remote().main_memory().safely_at(addr, asize);
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
	if (machine.has_remote())
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
	return AllocationResult{ptr, size, -1};
}
vMemory::AllocationResult
	vMemory::allocate_filebacked_memory(const MachineOptions& options, size_t size)
{
	if (options.mmap_backed_files) {
		throw std::runtime_error("Incompatible options: mmap_backed_files and allocate_file_backed_memory()");
	}
	if (size < 0x1000L) {
		memory_exception("Not enough guest memory", 0, size);
	}
	// Add the cold start state area
	size += ColdStartStateSize();
	// Open the to-be memory-mapped file
	const std::string& filename = options.snapshot_file;
	if (filename.empty()) {
		throw std::runtime_error("No VM snapshot file specified");
	}
	int fd = open(filename.c_str(), O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		if (errno != ENOENT) {
			throw std::runtime_error("Failed to open VM snapshot file: " + filename);
		}
		fd = open(filename.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
		if (fd < 0) {
			throw std::runtime_error("Failed to create VM snapshot file: " + filename);
		}
	}
	struct stat st;
	if (fstat(fd, &st) != 0) {
		close(fd);
		throw std::runtime_error("Failed to stat VM snapshot file: " + filename);
	}
	bool already_right_size = (st.st_size == off_t(size));
	char* ptr = (char*)MAP_FAILED;
	// If the file is not the correct size, resize it
	if (!already_right_size) {
		if (st.st_size != 0) {
			close(fd);
			throw std::runtime_error("VM snapshot file has incorrect size: " + filename);
		}
		// Create the file with the correct size
		if (ftruncate(fd, size) != 0) {
			close(fd);
			throw std::runtime_error("Failed to set size of VM snapshot file: " + filename);
		}
		ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_SHARED | MAP_NORESERVE, fd, 0);
	} else {
		// Map an existing file, which should not be modified on disk
		ptr = (char*) mmap(NULL, size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_NORESERVE, fd, 0);
		// Advise the kernel that we will be immediately accessing this memory's
		// state and user region
		madvise(ptr + size - ColdStartStateSize(), vMemory::PageSize(), MADV_WILLNEED);
	}
	close(fd);
	if (ptr == MAP_FAILED) {
		memory_exception("Failed to mmap VM snapshot file", 0, size);
	}
	return AllocationResult{ptr, size - ColdStartStateSize(), fd};
}

vMemory vMemory::New(Machine& m, const MachineOptions& options,
	uint64_t phys, uint64_t safe, size_t size)
{
	if (UNLIKELY(phys & 0xFFFFF))
		throw MachineException("Invalid physical memory alignment. Must be at least 2MB aligned.", phys);
	// Over-allocate in order to avoid trouble with 2MB-aligned operations
	size = vMemory::overaligned_memsize(size);
	// Use file-backed memory if requested
	if (!options.snapshot_file.empty()) {
		const auto [res_ptr, res_size, fd] = allocate_filebacked_memory(options, size);
		return vMemory(m, options, phys, safe, res_ptr, res_size, fd);
	}
	// Normal 2MB main memory allocation
	const auto [res_ptr, res_size, fd] = allocate_mapped_memory(options, size);
	return vMemory(m, options, phys, safe, res_ptr, res_size, -1);
}

VirtualMem vMemory::vmem() const
{
	return VirtualMem::New(physbase, ptr, size, remote_end);
}

MemoryBank::Page vMemory::new_page()
{
	return banks.get_available_bank(1u).get_next_page(1u);
}
MemoryBank::Page vMemory::new_hugepage()
{
	return banks.get_available_bank(512u).get_next_page(512u);
}

char* vMemory::get_writable_page(uint64_t addr, uint64_t flags, bool zeroes, bool dirty)
{
//	printf("*** Need a writable page at 0x%lX  (%s)\n", addr, (zeroes) ? "zeroed" : "copy");
	if (machine.has_remote() && machine.is_foreign_address(addr)) {
		// When connected to a remote VM, we can access the remote kernel memory
		return machine.remote().main_memory().get_writable_page(addr, flags, zeroes, dirty);
	}

	WritablePageOptions zero_opts;
	zero_opts.zeroes = zeroes;
	auto writable_page = writable_page_at(*this, addr, flags, zero_opts);
	if (dirty) {
		writable_page.set_dirty();
	}
	return writable_page.page;
}

char* vMemory::get_kernelpage_at(uint64_t addr) const
{
	if (machine.has_remote() && machine.is_foreign_address(addr)) {
		// When connected to a remote VM, we can access the remote kernel memory
		return machine.remote().main_memory().get_kernelpage_at(addr);
	}
#ifdef TINYKVM_ARCH_AMD64
	constexpr uint64_t flags = PDE64_PRESENT;
	return readable_page_at(*this, addr, flags);
#else
#error "Implement me!"
#endif
}

char* vMemory::get_userpage_at(uint64_t addr) const
{
	if (machine.has_remote() && machine.is_foreign_address(addr)) {
		// When connected to a remote VM, we can access the remote kernel memory
		return machine.remote().main_memory().get_userpage_at(addr);
	}
#ifdef TINYKVM_ARCH_AMD64
	constexpr uint64_t flags = PDE64_PRESENT | PDE64_USER;
	return readable_page_at(*this, addr, flags);
#else
#error "Implement me!"
#endif
}

std::vector<std::pair<uint64_t, uint64_t>> Machine::get_accessed_pages() const
{
	return tinykvm::get_accessed_pages(this->main_memory());
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
void vMemory::memory_exception(const char* msg, uint64_t addr, uint64_t size, bool oom)
{
	throw MemoryException(msg, addr, size, oom);
}

void vMemory::increment_unlocked_pages(size_t pages)
{
	if (this->main_memory_writes) {
		this->unlocked_pages += pages;
		if (this->unlocked_pages > this->banks.max_pages()) {
			memory_exception("Out of working memory",
				this->unlocked_pages * PAGE_SIZE, this->banks.max_pages() * PAGE_SIZE, true);
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
