#include <stdio.h>
#include <unistd.h>

extern int remote_function(int (*arg)(int), int value)
{
	//write(1, "In remote_function\n", 20);
	return arg(value);
}

int main()
{
	printf("Hello from Storage!\n");
	return 0;
}
