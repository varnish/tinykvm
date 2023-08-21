#include <exception>
#include <stdio.h>
extern int remote_function(int(*callback)(int), int value);
extern int remote_throw(int value);

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

extern "C"
int do_calculation(int value)
{
	try {
		return remote_throw(value);
	} catch (const std::exception& e) {
		printf("Exception caught: %s\n", e.what());
	} catch (...) {
		printf("Unknown exception caught\n");
	}
	return 0;
}

int simple_calculation(int value)
{
	return value;
}
