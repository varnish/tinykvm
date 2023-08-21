#include <cstdio>
#include <stdexcept>

thread_local int tls_value = 42;

int remote_function(int (*arg)(int), int value)
{
	return arg(value);
}

int remote_throw(int value)
{
	try {
		throw std::runtime_error("Remotely throw exception!");
	} catch (const std::exception& e) {
		printf("Exception handled remotely: %s\n", e.what());
		return tls_value;
	}
	return -1;
}

int main()
{
	printf("Hello from Storage!\n");
	return 0;
}
