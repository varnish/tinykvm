#pragma once
#include "../memory.hpp"
#include <functional>

namespace tinykvm {

extern uint64_t setup_amd64_paging(vMemory&,
	std::string_view binary,
	const std::vector<VirtualRemapping>& remappings,
	bool split_hugepages);
extern void print_pagetables(const vMemory&);

using foreach_page_t = std::function<void(uint64_t, uint64_t&, size_t)>;
extern void foreach_page(vMemory&, foreach_page_t callback);
extern void foreach_page(const vMemory&, foreach_page_t callback);
extern void foreach_page_makecow(vMemory&, uint64_t kernel_end, uint64_t shared_memory_boundary);

extern void page_at(vMemory&, uint64_t addr, foreach_page_t);
extern char * writable_page_at(vMemory&, uint64_t addr, uint64_t flags, bool zeroes = false);
extern char * readable_page_at(const vMemory&, uint64_t addr, uint64_t flags);

static inline bool page_is_zeroed(const uint64_t* page) {
	for (size_t i = 0; i < 512; i += 8) {
		if ((page[i+0] | page[i+1] | page[i+2] | page[i+3]) != 0 ||
			(page[i+4] | page[i+5] | page[i+6] | page[i+7]) != 0)
			return false;
	}
	return true;
}

} // tinykvm
