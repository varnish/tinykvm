#include <cstdint>

namespace tinykvm {

	extern void page_duplicate(uint64_t* dest, const uint64_t* source);
	extern void page_memzero(uint64_t* dest);

}
