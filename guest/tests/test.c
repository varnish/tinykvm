#include <malloc.h>
#include <stdio.h>
#include <string.h>

static long nprimes = 0;

int main(int argc, char** argv)
{
	char* test = (char *)malloc(14);
	strcpy(test, argv[1]);
	printf("%.*s\n", 13, test);
	free(test);

	static const int N = 1000000;
	char prime[N];
	memset(prime, 1, sizeof(prime));
	for (long n = 2; n < N; n++)
	{
		if (prime[n]) {
			nprimes += 1;
			for (long i = n*n; i < N; i += n)
				prime[i] = 0;
		}
	}
	return 666;
}

#include <assert.h>
static int t = 0;

__attribute__((used))
int test_return()
{
	t = 1;
	return 666;
}

__attribute__((used))
void test_ud2()
{
	asm("ud2");
}

__attribute__((used))
int test_read()
{
	assert(nprimes == 78498);
	return 200;
}

__attribute__((used))
void test_write()
{
	assert(t == 0);
	t = 1;
	asm("" ::: "memory");
	assert(t == 1);
}

static int cow = 0;

__attribute__((used))
int test_copy_on_write()
{
	assert(cow == 0);
	cow = 1;
	return 666;
}
