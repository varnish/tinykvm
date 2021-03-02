#include "api.hpp"

size_t strlen(const char *str)
{
	const char *s = str;
	while (*s) s++;
	return s - str;
}

inline void kprint(const char* string, size_t len) {
	syscall(1, string, len);
}
inline void kprint(const char* string) {
	kprint(string, strlen(string));
}

int main(int argc, char** argv)
{
/*	for (int i = 0; i < argc; i++) {
		kprint(argv[i]);
	}*/

	//asm("hlt");
	//syscall(158, 0x1003, 0x5678);
	//native_syscall(158, 0x1003, 0x5678);

	return 0x123;
}

struct Data {
	char   buffer[128];
	size_t len;
};

#include <immintrin.h>
PUBLIC(uint32_t empty(const Data& data))
{
	volatile __m256i xmm0;
	xmm0 = _mm256_set_epi32(1, 2, 3, 4, 5, 6, 7, 8);

	kprint(data.buffer, data.len);

	return crc32c_sse42(data.buffer, data.len);;
}
