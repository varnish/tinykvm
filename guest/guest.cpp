#include <cstddef>
static const char text[] = "Hello World!\n";

asm(".global syscall\n"
"syscall:\n"
"	add $0xffffa000, %edi\n"
"	movl $0, (%rdi)\n"
"   ret\n");
extern "C" long syscall(int scall, ...);

extern "C" void exit(int code) {
	syscall(0, code);
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

extern "C" __attribute__((used))
int empty(const Data& data)
{
	syscall(1, data.buffer, data.len);
	return 0;
}
