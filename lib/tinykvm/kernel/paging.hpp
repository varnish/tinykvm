#pragma once
#include "../memory.hpp"

namespace tinykvm {

extern uint64_t setup_amd64_paging(vMemory&, uint64_t pagetable_base,
	uint64_t except_addr, uint64_t ist_addr, std::string_view binary);
extern void print_pagetables(vMemory&, uint64_t pagetable_base);

}
