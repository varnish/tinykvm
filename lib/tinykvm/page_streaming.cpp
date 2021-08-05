#include "page_streaming.hpp"
#include <cstring>

#define ENABLE_AVX2_PAGE_UTILS
#if defined(ENABLE_AVX2_PAGE_UTILS)
#include <x86intrin.h>
#endif

namespace tinykvm {

void page_duplicate(uint64_t* dest, const uint64_t* source)
{
#if defined(__AVX2__) && defined(ENABLE_AVX2_PAGE_UTILS)
	for (size_t i = 0; i < 16; i++) {
		auto i0 = _mm256_stream_load_si256((__m256i *)&source[4 * 0]);
		auto i1 = _mm256_stream_load_si256((__m256i *)&source[4 * 1]);
		auto i2 = _mm256_stream_load_si256((__m256i *)&source[4 * 2]);
		auto i3 = _mm256_stream_load_si256((__m256i *)&source[4 * 3]);
		auto i4 = _mm256_stream_load_si256((__m256i *)&source[4 * 4]);
		auto i5 = _mm256_stream_load_si256((__m256i *)&source[4 * 5]);
		auto i6 = _mm256_stream_load_si256((__m256i *)&source[4 * 6]);
		auto i7 = _mm256_stream_load_si256((__m256i *)&source[4 * 7]);

		_mm256_stream_pd((double *)&dest[4 * 0], *(__m256d *) &i0);
		_mm256_stream_pd((double *)&dest[4 * 1], *(__m256d *) &i1);
		_mm256_stream_pd((double *)&dest[4 * 2], *(__m256d *) &i2);
		_mm256_stream_pd((double *)&dest[4 * 3], *(__m256d *) &i3);
		_mm256_stream_pd((double *)&dest[4 * 4], *(__m256d *) &i4);
		_mm256_stream_pd((double *)&dest[4 * 5], *(__m256d *) &i5);
		_mm256_stream_pd((double *)&dest[4 * 6], *(__m256d *) &i6);
		_mm256_stream_pd((double *)&dest[4 * 7], *(__m256d *) &i7);
		dest   += 4 * 8;
		source += 4 * 8;
	}
#else
	std::memcpy(dest, source, 4096);
#endif
}

void page_memzero(uint64_t* dest)
{
#if defined(__AVX2__) && defined(ENABLE_AVX2_PAGE_UTILS)
	auto iz = _mm256_setzero_si256();
	for (size_t i = 0; i < 16; i++) {
		_mm256_stream_pd((double *)&dest[4 * 0], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 1], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 2], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 3], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 4], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 5], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 6], *(__m256d *) &iz);
		_mm256_stream_pd((double *)&dest[4 * 7], *(__m256d *) &iz);
		dest   += 4 * 8;
	}
#else
	std::memset(dest, 0, 4096);
#endif
}

} // tinykvm
