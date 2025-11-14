#pragma once
#include "../memory.hpp"
#include <functional>

namespace tinykvm {

extern uint64_t setup_amd64_paging(vMemory&,
	std::string_view binary,
	const std::vector<VirtualRemapping>& remappings,
	bool split_hugepages,
	bool split_all_hugepages_during_loading);
extern void print_pagetables(const vMemory&);

using foreach_page_t = std::function<void(uint64_t, uint64_t&, size_t)>;
extern void foreach_page(vMemory&, foreach_page_t callback, bool skip_oob_addresses = true);
extern void foreach_page(const vMemory&, foreach_page_t callback, bool skip_oob_addresses = true);
extern void foreach_page_makecow(vMemory&, uint64_t kernel_end, uint64_t shared_memory_boundary);
extern std::vector<std::pair<uint64_t, uint64_t>> get_accessed_pages(const vMemory& memory);

extern void page_at(vMemory&, uint64_t addr, foreach_page_t, bool ignore_missing = false);
struct WritablePage {
	char *page;
	uint64_t& entry;
	size_t size;

	void set_dirty(); // paging.cpp
	void set_protections(int prot); // paging.cpp
};
struct WritablePageOptions {
	bool zeroes = false;
	bool allow_dirty = false;
};
extern WritablePage writable_page_at(vMemory&, uint64_t addr, uint64_t flags, WritablePageOptions = {});
extern char * readable_page_at(const vMemory&, uint64_t addr, uint64_t flags);
// Merges leaf pages back into hugepages where possible. Returns number of merged pages.
extern size_t paging_merge_leaf_pages_into_hugepages(vMemory&, bool merge_if_dirty = false);

static inline bool page_is_zeroed(const uint64_t* page) {
	for (size_t i = 0; i < 512; i += 8) {
		if ((page[i+0] | page[i+1] | page[i+2] | page[i+3]) != 0 ||
			(page[i+4] | page[i+5] | page[i+6] | page[i+7]) != 0)
			return false;
	}
	return true;
}

static constexpr inline uint64_t PageMask() {
	return vMemory::PageSize() - 1UL;
}

} // tinykvm
