#include <cstdint>
#include <cstring>
//#define ENABLE_AVX2_PAGE_UTILS

namespace tinykvm {

#ifdef ENABLE_AVX2_PAGE_UTILS
	extern void page_duplicate(uint64_t* dest, const uint64_t* source);
	extern void page_memzero(uint64_t* dest);
#else
	inline void page_duplicate(uint64_t* dest, const uint64_t* source)
	{
		std::memcpy(dest, source, 4096);
	}

	inline void page_memzero(uint64_t* dest)
	{
		std::memset(dest, 0, 4096);
	}
#endif

	extern void avx2_page_duplicate(uint64_t* dest, const uint64_t* source);

}
