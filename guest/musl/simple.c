#include <assert.h>

int main()
{
	return 0;
}

static int t = 0;

__attribute__((used))
void bench()
{
	//assert(t == 0);
	//t = 1;
}

__attribute__((used))
void bench_write()
{
	assert(t == 0);
	t = 1;
}

asm(".global one_vmexit\n" \
".type one_vmexit, function\n" \
"one_vmexit:\n" \
"	out %ax, $1\n" \
"	ret\n");
extern void one_vmexit();

__attribute__((used))
void bench_vmexits(int count)
{
	while (count--) one_vmexit();
}
