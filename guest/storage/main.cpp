#include <stdio.h>
extern "C" int remote_function(int(*callback)(int), int value);

static int double_int(int value)
{
	return value * 2;
}

int main()
{
	printf("Hello from Main VM!\n");
	fflush(stdout);
	for (int i = 0; i < 10; i++) {
		const int val = remote_function(double_int, 21);
		printf("Returned value: %d\n", val);
	}
	return 0;
}

extern "C" int do_calculation(int value)
{
	return remote_function(double_int, value);
}
extern "C" void do_nothing(int) { }
