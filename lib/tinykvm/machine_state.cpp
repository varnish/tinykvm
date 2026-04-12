#include "machine.hpp"

#include <algorithm>
#include <cstring>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stdexcept>
#include <span>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#ifdef TINYKVM_ARCH_AMD64
#include "amd64/amd64.hpp"
#include "amd64/memory_layout.hpp"
#include "amd64/paging.hpp"
#endif
#include "linux/fds.hpp"
#include "linux/threads.hpp"

namespace tinykvm {

struct ColdStartAccessedRange {
	uint64_t start;
	uint64_t end;
};

struct ColdStartThreadState {
	int tid;
	tinykvm_x86regs    regs;
	uint64_t 		   fsbase;
	uint64_t 		   clear_tid;
};
struct ColdStartThreads {
	size_t count;
	int current_tid;
};

struct ColdStartFds {
	// Note: We don't store *any* file descriptors, just the metadata
	// to reconstruct epoll event loops and socket pairs
	size_t epoll_entries;
	size_t socket_pairs;
	int next_vfd;
};
struct ColdStartEpollEntry {
	size_t epoll_fds;
	size_t shared_epoll_fds;
	int vfd;
};
struct ColdStartEpollFd {
	int vfd;
	struct epoll_event event;
};
struct ColdStartSharedEpollFd {
	int vfd;
};

struct ColdStartSocketPair {
	int vfd1;
	int vfd2;
	int type;
};

struct SnapshotState {
	static constexpr uint32_t MAGIC = 0x564D4353; // 'VMCS'
	uint32_t magic;
	uint32_t size;
	tinykvm_x86regs    regs;
	kvm_sregs          sregs;
	tinykvm_x86fpuregs fpu;
	bool m_prepped;
	bool m_forked;
	bool m_just_reset;
	bool m_relocate_fixed_mmap;

	Machine::address_t m_image_base;
	Machine::address_t m_stack_address;
	Machine::address_t m_heap_address;
	Machine::address_t m_brk_address;
	Machine::address_t m_brk_end_address;
	Machine::address_t m_start_address;
	Machine::address_t m_kernel_end;
	//MMapCache m_mmap_cache;
	Machine::address_t mmap_current;

	Machine::address_t m_page_tables;
	bool main_memory_writes;
	uint32_t num_access_ranges;

	char current[0];

	static constexpr size_t Size() noexcept { return vMemory::ColdStartStateSize(); }

	template <typename T>
	T* next(void*& current) {
		T* ret = reinterpret_cast<T*>(current);
		current = reinterpret_cast<char*>(current) + sizeof(T);
		// Bounds-check against end-of-structure
		if (reinterpret_cast<char*>(current) > reinterpret_cast<char*>(this) + Size()) {
			throw std::runtime_error("Out of bounds access on SnapshotState");
		}
		return ret;
	}
};
bool Machine::load_snapshot_state()
{
	if (!memory.has_loadable_snapshot_state()) {
		return false;
	}
	if (!this->memory.has_snapshot_area()) {
		throw std::runtime_error("No snapshot state area allocated");
	}
	if (this->is_forked()) {
		throw std::runtime_error("Cannot load snapshot state into a forked VM");
	}
	void* map = this->memory.get_snapshot_state_area();
	SnapshotState& state = *reinterpret_cast<SnapshotState*>(map);
	if (state.magic != SnapshotState::MAGIC) {
		throw std::runtime_error("No valid snapshot state found");
	}
	if (state.size < sizeof(SnapshotState) || state.size > SnapshotState::Size()) {
		fprintf(stderr, "Invalid snapshot state size: %u\n", state.size);
		throw std::runtime_error("Invalid snapshot state size");
	}

	// Load the state into the VM
	try {
		this->set_registers(state.regs);
		this->set_special_registers(state.sregs);
		this->set_fpu_registers(state.fpu);
		this->m_prepped = state.m_prepped;
		this->m_forked = state.m_forked;
		this->m_just_reset = state.m_just_reset;
		this->m_relocate_fixed_mmap = state.m_relocate_fixed_mmap;
		this->m_image_base = state.m_image_base;
		this->m_stack_address = state.m_stack_address;
		this->m_heap_address = state.m_heap_address;
		this->m_brk_address = state.m_brk_address;
		this->m_brk_end_address = state.m_brk_end_address;
		this->m_start_address = state.m_start_address;
		this->m_kernel_end = state.m_kernel_end;
		this->m_mmap_cache.current() = state.mmap_current;
		this->memory.main_memory_writes = state.main_memory_writes;
		this->memory.page_tables = state.m_page_tables;

		void* current = state.current;
		// Load populate pages
		madvise(this->memory.ptr, kernel_end_address(), MADV_WILLNEED | MADV_SEQUENTIAL);
		static constexpr uint64_t step = 1*1024*1024;
		static constexpr uint64_t madvise_max_total = 32 * 1024 * 1024;
		uint64_t madvised_total = 0;
		int madvised_total_calls = 0;
		for (unsigned i = 0; i < state.num_access_ranges; i++) {
			ColdStartAccessedRange* range = state.next<ColdStartAccessedRange>(current);
			if (range->start >= MemoryBanks::ARENA_BASE_ADDRESS || range->start < kernel_end_address())
				continue;
			if (madvised_total >= madvise_max_total)
				continue;
			try {
				//printf("Populating pages from 0x%lX -> 0x%lX\n", range->start, range->end);
				for (uint64_t start = range->start; start < range->end; start += step) {
					madvise(this->memory.ptr + start, std::min(range->end - start, step), MADV_WILLNEED | MADV_SEQUENTIAL);
					madvised_total += std::min(range->end - start, step);
					madvised_total_calls++;
					//printf("Madvised pages from 0x%lX -> 0x%lX (total madvised: %zu MiB)\n",
					//	start, std::min(start + step, range->end), madvised_total / (1024 * 1024));
					if (madvised_total >= madvise_max_total) {
						break;
					}
				}
			} catch (const std::exception& e) {
				fprintf(stderr, "Failed to access page at 0x%lX: %s\n", range->start, e.what());
				continue;
			}
		}
		//printf("Madvised a total of %zu MiB of pages in %d calls\n",
		// 	madvised_total / (1024 * 1024), madvised_total_calls);

		// Load the thread states
		ColdStartThreads* threads = state.next<ColdStartThreads>(current);
		if (threads->count > 0) {
			auto& mt = this->threads();
			for (size_t i = 0; i < threads->count; i++) {
				ColdStartThreadState* tstate = state.next<ColdStartThreadState>(current);
				Thread& thread = mt.create(tstate->tid);
				thread.stored_regs = tstate->regs;
				thread.fsbase = tstate->fsbase;
				thread.clear_tid = tstate->clear_tid;
			}
			mt.set_to_and_suspend_others(threads->current_tid);
		}
		// Load the file descriptor states
		ColdStartFds* fds = state.next<ColdStartFds>(current);
		auto& fdm = this->fds();
		fdm.set_vfd_start(fds->next_vfd);
		// Create socket pairs first
		for (size_t i = 0; i < fds->socket_pairs; i++) {
			ColdStartSocketPair* csp = state.next<ColdStartSocketPair>(current);
			FileDescriptors::SocketPair sp;
			sp.vfd1 = csp->vfd1;
			sp.vfd2 = csp->vfd2;
			sp.type = FileDescriptors::SocketType(csp->type);
			fdm.add_socket_pair(sp);
			// Create the (real) socket pairs and manage them
			fdm.create_socket_pairs_from(sp);
		}
		// Create epoll entries
		for (size_t i = 0; i < fds->epoll_entries; i++) {
			ColdStartEpollEntry* centry = state.next<ColdStartEpollEntry>(current);
			auto& entry = fdm.get_epoll_entry_for_vfd(centry->vfd);
			for (size_t j = 0; j < centry->epoll_fds; j++) {
				ColdStartEpollFd* cefd = state.next<ColdStartEpollFd>(current);
				entry.epoll_fds[cefd->vfd] = cefd->event;
			}
			for (size_t j = 0; j < centry->shared_epoll_fds; j++) {
				ColdStartSharedEpollFd* csefd = state.next<ColdStartSharedEpollFd>(current);
				entry.shared_epoll_fds.insert(csefd->vfd);
			}
			// Create the (real) epoll system and manage it
			fdm.create_epoll_entry_from(centry->vfd, entry);
		}

	} catch (const MachineException& me) {
		fprintf(stderr, "Failed to set cold start state: %s Data: 0x%#lX\n",
			me.what(), me.data());
		return false;
	}
	return true;
}
std::vector<std::pair<uint64_t, uint64_t>> Machine::reorder_snapshot_memory(const std::vector<uint64_t>& fault_order)
{
	const uint64_t physbase = this->memory.physbase;
	const uint64_t mem_size = this->memory.size;
	const uint64_t kernel_end = this->kernel_end_address();
	const uint64_t FIXED_REGION_END = kernel_end;
	const uint64_t arena_base = MemoryBanks::ARENA_BASE_ADDRESS;
	char* const ptr = this->memory.ptr;

	// Step 1: Collect all pages from the page tables
	auto all_pages = collect_all_pages(this->memory, true);

	// Deduplicate pages (a physical address may appear as both branch and leaf
	// in edge cases, or the same page table page may be referenced multiple times)
	std::unordered_set<uint64_t> seen;
	std::vector<PageInfo> unique_pages;
	unique_pages.reserve(all_pages.size());
	for (auto& pi : all_pages) {
		if (seen.insert(pi.paddr).second) {
			unique_pages.push_back(pi);
		}
	}

	// Step 2: Sort pages into categories
	// Build fault order lookup: paddr -> order index
	std::unordered_map<uint64_t, size_t> fault_index;
	fault_index.reserve(fault_order.size());
	for (size_t i = 0; i < fault_order.size(); i++) {
		fault_index.insert_or_assign(fault_order[i], i);
	}

	// Separate into categories.
	// Pages below FIXED_REGION_END are fixed kernel structures (GDT, TSS, IDT, etc.)
	// and must remain at their exact physical addresses.
	// Bank pages (>= ARENA_BASE_ADDRESS) are CoW copies from setup_cow_mode that
	// need to be flattened into main memory — they go into branch_pages.
	std::vector<PageInfo> fixed_pages, kernel_pages, faulted_pages, unfaulted_pages, branch_pages;
	for (auto& pi : unique_pages) {
		if (pi.paddr >= arena_base) {
			// Bank page — must be flattened into main memory
			branch_pages.push_back(pi);
		} else if (pi.paddr < FIXED_REGION_END) {
			fixed_pages.push_back(pi);
		} else if (pi.is_branch) {
			branch_pages.push_back(pi);
		} else if (pi.paddr < kernel_end) {
			kernel_pages.push_back(pi);
		} else {
			auto it = fault_index.find(pi.paddr);
			if (it != fault_index.end()) {
				faulted_pages.push_back(pi);
			} else {
				unfaulted_pages.push_back(pi);
			}
		}
	}

	// Sort kernel pages by address
	std::sort(kernel_pages.begin(), kernel_pages.end(),
		[](const PageInfo& a, const PageInfo& b) { return a.paddr < b.paddr; });
	// Sort faulted pages by fault order
	std::sort(faulted_pages.begin(), faulted_pages.end(),
		[&](const PageInfo& a, const PageInfo& b) {
			return fault_index[a.paddr] < fault_index[b.paddr];
		});
	// Sort unfaulted pages by address
	std::sort(unfaulted_pages.begin(), unfaulted_pages.end(),
		[](const PageInfo& a, const PageInfo& b) { return a.paddr < b.paddr; });
	// Sort branch pages by address
	std::sort(branch_pages.begin(), branch_pages.end(),
		[](const PageInfo& a, const PageInfo& b) { return a.paddr < b.paddr; });

	// Concatenate in order: kernel, faulted user, unfaulted user, branch (page tables)
	// Fixed pages are excluded — they keep their original addresses.
	std::vector<PageInfo> ordered;
	ordered.reserve(unique_pages.size());
	ordered.insert(ordered.end(), kernel_pages.begin(), kernel_pages.end());
	ordered.insert(ordered.end(), faulted_pages.begin(), faulted_pages.end());
	ordered.insert(ordered.end(), unfaulted_pages.begin(), unfaulted_pages.end());
	ordered.insert(ordered.end(), branch_pages.begin(), branch_pages.end());

	// Step 3: Assign new sequential addresses
	// Fixed pages keep their identity mapping
	std::unordered_map<uint64_t, uint64_t> translation;
	translation.reserve(ordered.size() + fixed_pages.size());
	for (auto& pi : fixed_pages) {
		translation[pi.paddr] = pi.paddr; // identity — no move
	}
	// Movable pages start after the fixed region.
	// Assign addresses sequentially, but stop accepting pages if we'd
	// exceed the allocation. Pages that don't fit are dropped — unfaulted
	// pages at the tail are the ones most likely trimmed, since they
	// weren't accessed during the probing request anyway.
	const uint64_t mem_limit = physbase + mem_size;
	uint64_t cursor = FIXED_REGION_END;
	size_t pages_placed = 0;
	for (auto& pi : ordered) {
		uint64_t aligned = (cursor + (pi.size - 1)) & ~(pi.size - 1);
		if (aligned + pi.size > mem_limit)
			break;
		translation[pi.paddr] = aligned;
		cursor = aligned + pi.size;
		pages_placed++;
	}
	// Trim ordered to only the pages that fit
	const size_t pages_dropped = ordered.size() - pages_placed;
	ordered.resize(pages_placed);
	if (pages_dropped > 0) {
		printf("reorder_snapshot_memory: dropped %zu pages that didn't fit after alignment\n",
			pages_dropped);
	}

	// Step 4: Copy pages to temporary buffer in new order
	char* tmp = (char*)mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (tmp == MAP_FAILED) {
		fprintf(stderr, "reorder_snapshot_memory: failed to allocate temp buffer, skipping\n");
		return {};
	}

	// Copy fixed region as-is (pages below FIXED_REGION_END stay in place)
	std::memcpy(tmp, ptr, FIXED_REGION_END - physbase);
	// Copy movable pages to their new locations.
	// Bank pages (>= ARENA_BASE_ADDRESS) must be read via memory.page_at()
	// since they're not in the main memory mmap.
	for (auto& pi : ordered) {
		uint64_t new_paddr = translation[pi.paddr];
		const char* src;
		if (pi.paddr >= arena_base) {
			src = (const char*)this->memory.page_at(pi.paddr);
		} else {
			src = ptr + (pi.paddr - physbase);
		}
		std::memcpy(tmp + (new_paddr - physbase), src, pi.size);
	}

	// Step 5: Rewire page tables in the temp buffer
	uint64_t new_root = translation.at(this->memory.page_tables);
	rewire_page_tables(tmp, physbase, new_root, translation, true);

	// Step 6: Copy back and update metadata
	std::memcpy(ptr, tmp, mem_size);
	munmap(tmp, mem_size);
	this->memory.page_tables = new_root;

	// Update KVM CR3 to match the new page table root.
	// setup_cow_mode set CR3 to a bank address which won't exist on load.
	auto sregs = this->get_special_registers();
	sregs.cr3 = new_root;
	this->set_special_registers(sregs);

	printf("Reordered snapshot memory: %zu pages (%zu fixed, %zu kernel, %zu faulted, %zu unfaulted, %zu branch)\n",
		ordered.size() + fixed_pages.size(), fixed_pages.size(), kernel_pages.size(),
		faulted_pages.size(), unfaulted_pages.size(), branch_pages.size());

	// Build post-reorder populate pages from only the pages that were
	// actually accessed during the probing request (+ kernel and branch
	// pages needed for page table infrastructure).  Unfaulted pages are
	// still present in the snapshot but should not be prefetched — they
	// can be demand-paged if a future request happens to need them.
	std::vector<std::pair<uint64_t, uint64_t>> populate_pages;
	populate_pages.reserve(kernel_pages.size() + faulted_pages.size() + branch_pages.size());
	auto add_translated = [&](const std::vector<PageInfo>& pages) {
		for (auto& pi : pages) {
			auto it = translation.find(pi.paddr);
			if (it != translation.end()) {
				populate_pages.push_back({it->second, pi.size});
			}
		}
	};
	add_translated(kernel_pages);
	add_translated(faulted_pages);
	add_translated(branch_pages);
	return populate_pages;
}

void Machine::save_snapshot_state_now(const std::vector<std::pair<uint64_t, uint64_t>>& populate_pages) const
{
	if (this->is_forked()) {
		throw std::runtime_error("Cannot save snapshot state of a forked VM");
	}
	void* map = this->memory.get_snapshot_state_area();
	SnapshotState& state = *reinterpret_cast<SnapshotState*>(map);
	try {
		state.magic = SnapshotState::MAGIC;
		state.size  = 0; // Invalid (for now)
		state.regs  = this->registers();
		state.sregs = this->get_special_registers();
		state.fpu   = this->fpu_registers();
		state.m_prepped = this->m_prepped;
		state.m_forked = this->m_forked;
		state.m_just_reset = this->m_just_reset;
		state.m_relocate_fixed_mmap = this->m_relocate_fixed_mmap;
		state.m_image_base = this->m_image_base;
		state.m_stack_address = this->m_stack_address;
		state.m_heap_address = this->m_heap_address;
		state.m_brk_address = this->m_brk_address;
		state.m_brk_end_address = this->m_brk_end_address;
		state.m_start_address = this->m_start_address;
		state.m_kernel_end = this->m_kernel_end;
		state.mmap_current = this->m_mmap_cache.current();
		state.main_memory_writes = this->memory.main_memory_writes;
		state.m_page_tables = this->memory.page_tables;

		void* current = state.current;
		// Save populate pages
		state.num_access_ranges = 0;
		if (!populate_pages.empty()) {
			uint64_t current_begin = 0;
			uint64_t current_end = 0;
			for (const auto& [page_addr, size] : populate_pages) {
				if (page_addr >= MemoryBanks::ARENA_BASE_ADDRESS || page_addr < kernel_end_address())
					continue;
				// Merge contiguous ranges
				if (current_end == page_addr) {
					current_end += size;
					continue;
				}
				// Store previous range
				if (current_end != current_begin) {
					ColdStartAccessedRange* range = state.next<ColdStartAccessedRange>(current);
					range->start = current_begin;
					range->end = current_end;
					state.num_access_ranges++;
				}
				// Start new range
				current_begin = page_addr;
				current_end = page_addr + size;
			}
			// Store last range
			if (current_end != current_begin) {
				ColdStartAccessedRange* range = state.next<ColdStartAccessedRange>(current);
				range->start = current_begin;
				range->end = current_end;
				state.num_access_ranges++;
			}
		}

		// Save the multi-threading state
		ColdStartThreads* threads = state.next<ColdStartThreads>(current);
		if (this->has_threads()) {
			threads->count = this->m_mt->size();
			threads->current_tid = this->m_mt->gettid();
			// Save each thread's state
			for (const auto& [tid, thread] : this->m_mt->threads()) {
				ColdStartThreadState* tstate = state.next<ColdStartThreadState>(current);
				tstate->tid = tid;
				tstate->regs = thread.stored_regs;
				tstate->fsbase = thread.fsbase;
				tstate->clear_tid = thread.clear_tid;
			}
		} else {
			threads->count = 0;
		}

		// Save the file descriptor states
		ColdStartFds* fds = state.next<ColdStartFds>(current);
		const auto& fdm = this->fds();
		fds->next_vfd = fdm.vfd_start();
		const auto& epoll_entries = fdm.get_epoll_entries();
		fds->epoll_entries = epoll_entries.size();
		fds->socket_pairs = fdm.get_socket_pairs().size();
		// Socket pair reconstruction entries
		for (const auto& sp : fdm.get_socket_pairs()) {
			ColdStartSocketPair* csp = state.next<ColdStartSocketPair>(current);
			if (sp.type == FileDescriptors::INVALID || sp.type == FileDescriptors::DUPFD) {
				// Silently ignore invalid or dupfd socket pairs that cannot be reconstructed
				// when re-loading the state anyway
				csp->vfd1 = -1;
				csp->vfd2 = -1;
				csp->type = int(FileDescriptors::INVALID);
				continue;
			}
			csp->vfd1 = sp.vfd1;
			csp->vfd2 = sp.vfd2;
			csp->type = int(sp.type);
		}
		// Epoll reconstruction entries
		for (const auto& [vfd, entry] : epoll_entries) {
			ColdStartEpollEntry* centry = state.next<ColdStartEpollEntry>(current);
			centry->vfd = vfd;
			centry->epoll_fds = entry->epoll_fds.size();
			centry->shared_epoll_fds = entry->shared_epoll_fds.size();
			for (const auto& [evfd, event] : entry->epoll_fds) {
				ColdStartEpollFd* cefd = state.next<ColdStartEpollFd>(current);
				cefd->vfd = evfd;
				cefd->event = event;
			}
			for (const auto& sevfd : entry->shared_epoll_fds) {
				ColdStartSharedEpollFd* csefd = state.next<ColdStartSharedEpollFd>(current);
				csefd->vfd = sevfd;
			}
		}

		// Finally, set the size
		state.size = static_cast<uint32_t>(
			reinterpret_cast<char*>(current) - reinterpret_cast<char*>(&state));
		if (state.size < sizeof(SnapshotState) || state.size > SnapshotState::Size()) {
			throw std::runtime_error("Snapshot state size was invalid");
		}

	} catch (const MachineException& me) {
		fprintf(stderr, "Failed to get snapshot state: %s Data: 0x%#lX\n",
			me.what(), me.data());
		state.magic = 0; // Invalidate
		throw std::runtime_error(std::string("Failed to get snapshot state: ") + me.what());
	} catch (const std::exception& e) {
		fprintf(stderr, "Failed to get snapshot state: %s\n", e.what());
		state.magic = 0; // Invalidate
		throw;
	}
}

void* vMemory::get_snapshot_state_area() const
{
	if (!this->has_snapshot_area()) {
		throw std::runtime_error("No snapshot state area allocated");
	}
	// The snapshot state area is after the end of the memory
	return (void*)(this->ptr + this->size);
}
bool vMemory::has_loadable_snapshot_state() const noexcept
{
	if (this->has_snapshot_area()) {
		void* area = this->get_snapshot_state_area();
		uint32_t* magic = reinterpret_cast<uint32_t*>(area);
		return *magic == SnapshotState::MAGIC;
	}
	return false;
}
void* Machine::get_snapshot_state_user_area() const
{
	if (!this->memory.has_snapshot_area()) {
		return nullptr;
	}
	void* map = this->memory.get_snapshot_state_area();
	SnapshotState& state = *reinterpret_cast<SnapshotState*>(map);
	if (state.magic != SnapshotState::MAGIC) {
		return nullptr;
	}
	if (state.size < sizeof(SnapshotState) || state.size > SnapshotState::Size()) {
		return nullptr;
	}
	// The user area is after the SnapshotState base + size
	return reinterpret_cast<char*>(map) + state.size;
}

} // namespace tinykvm
