#include <stdio.h>
extern int remote_function(int(*callback)(int), int value);

static int double_int(int value)
{
	return value * 2;
}

int main()
{
	printf("Jumping to %p\n", &remote_function);
	fflush(stdout);
	return remote_function(double_int, 21);
}

int do_calculation(int value)
{
	return remote_function(double_int, value);
}

int simple_calculation(int value)
{
	return value;
}
