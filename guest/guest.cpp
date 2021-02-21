#include "api.hpp"

size_t strlen(const char *str)
{
	const char *s = str;
	while (*s) s++;
	return s - str;
}

int main(int argc, char** argv)
{
	for (int i = 0; i < argc; i++) {
		syscall(1, argv[i], strlen(argv[i]));
	}
	return 0x123;
}

struct Data {
	char   buffer[128];
	size_t len;
};

#include <immintrin.h>

PUBLIC(int empty(const Data& data))
{
	volatile __m128i xmm0 __attribute__((aligned(16)));
	xmm0 = _mm_set_epi32(1, 2, 3, 4);

	syscall(1, data.buffer, data.len);
	return 0;
}
