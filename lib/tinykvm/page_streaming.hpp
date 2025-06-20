#include <cstdint>
#include <cstring>

namespace tinykvm {
	extern void avx2_page_duplicate(uint64_t* dest, const uint64_t* source);
	extern void avx2_page_memzero(uint64_t* dest);

	inline void page_duplicate(uint64_t* dest, const uint64_t* source)
	{
		//std::memcpy(dest, source, 4096);
		avx2_page_duplicate(dest, source);
	}

	inline void page_memzero(uint64_t* dest)
	{
		//std::memset(dest, 0, 4096);
		avx2_page_memzero(dest);
	}

}
