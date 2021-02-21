#pragma once
#include "../memory.hpp"

namespace tinykvm {

extern void setup_amd64_paging(vMemory& memory,
	uint64_t pagetable_base, uint64_t except_asm_addr, std::string_view binary);

}
