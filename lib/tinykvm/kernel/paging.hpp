#pragma once
#include "../memory.hpp"
#include <functional>

namespace tinykvm {

extern uint64_t setup_amd64_paging(vMemory&, std::string_view binary);
extern void print_pagetables(const vMemory&);

using foreach_page_t = std::function<void(uint64_t, uint64_t&, size_t)>;
extern void foreach_page(vMemory&, foreach_page_t callback);
extern void foreach_page(const vMemory&, foreach_page_t callback);
extern void foreach_page_makecow(vMemory&);

extern void page_at(vMemory&, uint64_t addr, foreach_page_t);
extern char * writable_page_at(vMemory&, uint64_t addr, bool zeroes = false);
extern char * readable_page_at(vMemory&, uint64_t addr, uint64_t flags);
}
