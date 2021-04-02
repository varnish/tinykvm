#pragma once
#include "../memory.hpp"
#include <functional>

namespace tinykvm {

extern uint64_t setup_amd64_paging(vMemory&, uint64_t pagetable_base,
	uint64_t except_addr, uint64_t ist_addr, std::string_view binary);
extern void print_pagetables(vMemory&, uint64_t pagetable_base);

using foreach_page_t = std::function<void(uint64_t, uint64_t, size_t)>;
extern void foreach_page(const vMemory&, uint64_t pt_base, foreach_page_t callback);

}
