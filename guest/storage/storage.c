#include <stdio.h>

extern int remote_function(int (*arg)(int), int value)
{
	return arg(value);
}

int main()
{
	printf("Hello from Storage!\n");
	return 0;
}
