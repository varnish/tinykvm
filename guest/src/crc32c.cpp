#include "api.hpp"

#include <immintrin.h>

inline bool ____is__aligned(const void* buffer, const int align) noexcept {
	return (((uintptr_t) buffer) & (align-1)) == 0;
}

uint32_t crc32c_sse42(const uint8_t* buffer, size_t len)
{
	uint32_t hash = 0xFFFFFFFF;
	// 8-bits until 4-byte aligned
	while (!____is__aligned(buffer, 4) && len > 0) {
		hash = _mm_crc32_u8(hash, *buffer); buffer++; len--;
	}
	// 16 bytes at a time
	while (len >= 16) {
		hash = _mm_crc32_u32(hash, *(uint32_t*) (buffer +  0));
		hash = _mm_crc32_u32(hash, *(uint32_t*) (buffer +  4));
		hash = _mm_crc32_u32(hash, *(uint32_t*) (buffer +  8));
		hash = _mm_crc32_u32(hash, *(uint32_t*) (buffer + 12));
		buffer += 16; len -= 16;
	}
	// 4 bytes at a time
	while (len >= 4) {
		hash = _mm_crc32_u32(hash, *(uint32_t*) buffer);
		buffer += 4; len -= 4;
	}
	// remaining bytes
	if (len & 2) {
		hash = _mm_crc32_u16(hash, *(uint16_t*) buffer);
		buffer += 2;
	}
	if (len & 1) {
		hash = _mm_crc32_u8(hash, *buffer);
	}
	return hash ^ 0xFFFFFFFF;
}
