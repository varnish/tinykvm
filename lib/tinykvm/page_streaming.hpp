#include <cstdint>
#include <cstring>
//#define ENABLE_AVX2_PAGE_UTILS

namespace tinykvm {
	extern void avx2_page_duplicate(uint64_t* dest, const uint64_t* source);
	extern void avx2_page_dupliteit(uint64_t* dest, const uint64_t* source);

#ifdef ENABLE_AVX2_PAGE_UTILS
	extern void page_duplicate(uint64_t* dest, const uint64_t* source);
	extern void page_memzero(uint64_t* dest);
#else
	inline void page_duplicate(uint64_t* dest, const uint64_t* source)
	{
		//std::memcpy(dest, source, 4096);
		avx2_page_duplicate(dest, source);
	}

	inline void page_memzero(uint64_t* dest)
	{
		std::memset(dest, 0, 4096);
	}
#endif

}
