#include "page_streaming.hpp"

#include <x86intrin.h>

namespace tinykvm {

void avx2_page_duplicate(uint64_t* dest, const uint64_t* source)
{
#if defined(__AVX512F__)
	for (size_t i = 0; i < 16; i++) {
		auto i0 = _mm512_load_si512((__m512i *)&source[8 * 0]);
		auto i1 = _mm512_load_si512((__m512i *)&source[8 * 1]);
		auto i2 = _mm512_load_si512((__m512i *)&source[8 * 2]);
		auto i3 = _mm512_load_si512((__m512i *)&source[8 * 3]);

		_mm512_store_si512((__m512i *)&dest[8 * 0], i0);
		_mm512_store_si512((__m512i *)&dest[8 * 1], i1);
		_mm512_store_si512((__m512i *)&dest[8 * 2], i2);
		_mm512_store_si512((__m512i *)&dest[8 * 3], i3);
		dest   += 8 * 4;
		source += 8 * 4;
	}
#elif defined(__avx2__)
	for (size_t i = 0; i < 16; i++) {
		auto i0 = _mm256_load_si256((__m256i *)&source[4 * 0]);
		auto i1 = _mm256_load_si256((__m256i *)&source[4 * 1]);
		auto i2 = _mm256_load_si256((__m256i *)&source[4 * 2]);
		auto i3 = _mm256_load_si256((__m256i *)&source[4 * 3]);
		auto i4 = _mm256_load_si256((__m256i *)&source[4 * 4]);
		auto i5 = _mm256_load_si256((__m256i *)&source[4 * 5]);
		auto i6 = _mm256_load_si256((__m256i *)&source[4 * 6]);
		auto i7 = _mm256_load_si256((__m256i *)&source[4 * 7]);

		_mm256_store_si256((__m256i *)&dest[4 * 0], *(__m256i *) &i0);
		_mm256_store_si256((__m256i *)&dest[4 * 1], *(__m256i *) &i1);
		_mm256_store_si256((__m256i *)&dest[4 * 2], *(__m256i *) &i2);
		_mm256_store_si256((__m256i *)&dest[4 * 3], *(__m256i *) &i3);
		_mm256_store_si256((__m256i *)&dest[4 * 4], *(__m256i *) &i4);
		_mm256_store_si256((__m256i *)&dest[4 * 5], *(__m256i *) &i5);
		_mm256_store_si256((__m256i *)&dest[4 * 6], *(__m256i *) &i6);
		_mm256_store_si256((__m256i *)&dest[4 * 7], *(__m256i *) &i7);
		dest   += 4 * 8;
		source += 4 * 8;
	}
#else
	std::memcpy(dest, source, 4096);
#endif
}
void avx2_page_memzero(uint64_t* dest)
{
#if defined(__AVX512F__)
	auto iz = _mm512_setzero_si512();
	for (size_t i = 0; i < 16; i++) {
		_mm512_store_si512((__m512i *)&dest[8 * 0], iz);
		_mm512_store_si512((__m512i *)&dest[8 * 1], iz);
		_mm512_store_si512((__m512i *)&dest[8 * 2], iz);
		_mm512_store_si512((__m512i *)&dest[8 * 3], iz);
		dest   += 8 * 4;
	}
#elif defined(__avx2__)
	auto iz = _mm256_setzero_si256();
	for (size_t i = 0; i < 16; i++) {
		_mm256_store_si256((__m256i *)&dest[4 * 0], iz);
		_mm256_store_si256((__m256i *)&dest[4 *	1], iz);
		_mm256_store_si256((__m256i *)&dest[4 * 2], iz);
		_mm256_store_si256((__m256i *)&dest[4 * 3], iz);
		_mm256_store_si256((__m256i *)&dest[4 * 4], iz);
		_mm256_store_si256((__m256i *)&dest[4 * 5], iz);
		_mm256_store_si256((__m256i *)&dest[4 * 6], iz);
		_mm256_store_si256((__m256i *)&dest[4 * 7], iz);
		dest   += 4 * 8;
	}
#else
	std::memset(dest, 0, 4096);
#endif
}

} // tinykvm
