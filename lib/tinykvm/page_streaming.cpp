#include "page_streaming.hpp"

#include <x86intrin.h>

namespace tinykvm {

#ifdef ENABLE_AVX2_PAGE_UTILS
void page_duplicate(uint64_t* dest, const uint64_t* source)
{
#if defined(__AVX2__)
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
#if defined(__AVX2__)
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
#endif

void avx2_page_duplicate(uint64_t* dest, const uint64_t* source)
{
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
}
void avx2_page_dupliteit(uint64_t* dest, const uint64_t* source)
{
	for (size_t i = 0; i < 16; i++) {
		#pragma unroll(8)
		for (int j = 0; j < 8; j++) {
			__m256i zmm = _mm256_load_si256((__m256i *)&source[4 * j]);
			int is_zero = _mm256_testz_si256(zmm, zmm);
			if (is_zero == 0)
			_mm256_store_si256((__m256i *)&dest[4 * j], zmm);
		}
		dest   += 4 * 8;
		source += 4 * 8;
	}
}

} // tinykvm
