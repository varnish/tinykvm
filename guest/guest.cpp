#include <cstddef>
static const char text[] = "Hello World!\n";

asm(".global syscall\n"
"syscall:\n"
"	add $0xffffa000, %edi\n"
"	movl $0, (%rdi)\n"
"   ret\n");
extern "C" long syscall(int scall, ...);

extern "C" __attribute__((noreturn)) void exit(int code) __THROW {
	syscall(0, code);
	__builtin_unreachable();
}

int main()
{
	syscall(1, text, sizeof(text)-1);
	return 0;
}

extern "C"
void _start()
{
	exit(main());
}

struct Data {
	char   buffer[128];
	size_t len;
};

#include <immintrin.h>
extern "C" __attribute__((used))
int empty(const Data& data)
{
	volatile __m128i xmm0 __attribute__((aligned(16)));
	xmm0 = _mm_set_epi32(1, 2, 3, 4);

	syscall(1, data.buffer, data.len);
	return 0;
}
