#include <malloc.h>
#include <stdio.h>
#include <string.h>
static void test_threads();
extern "C" int gettid();

int main()
{
	/*char* test = (char *)malloc(14);
	strcpy(test, "Hello World!\n");
	printf("%.*s", 13, test);*/

	test_threads();
	return 0;
}

__attribute__((used))
void test()
{
	/* */
}

asm(".global rexit\n"
	"rexit:\n"
	"mov %rax, %rdi\n"
	"mov $60, %rax\n"
	"syscall");

#include <cassert>
#include <pthread.h>
#include <sys/types.h>
#include <stdexcept>
#include <thread> // C++ threads
#include <vector>

struct testdata
{
	int depth     = 0;
	const int max_depth = 10;
	std::vector<pthread_t> threads;
};
static pthread_mutex_t mtx;

extern "C" {
	static void* thread_function1(void* data)
	{
		printf("Inside thread function1, x = %d\n", *(int*) data);
		thread_local int test = 2021;
		printf("test @ %p, test = %d\n", &test, test);
		assert(test == 2021);
		return NULL;
	}
	static void* thread_function2(void* data)
	{
		printf("Inside thread function2, x = %d\n", *(int*) data);
		thread_local int test = 2022;
		assert(test == 2022);
		pthread_mutex_lock(&mtx);

		printf("Yielding from thread2, expecting to be returned to main thread\n");
		sched_yield();
		printf("Returned to thread2, expecting to exit to after main thread yield\n");

		pthread_mutex_unlock(&mtx);
		pthread_exit(NULL);
	}
	static void* recursive_function(void* tdata)
	{
		auto* data = (testdata*) tdata;
		data->depth++;
		printf("%d: Thread depth %d / %d\n",
				gettid(), data->depth, data->max_depth);

		if (data->depth < data->max_depth)
		{
			pthread_t t;
			int res = pthread_create(&t, NULL, recursive_function, data);
			if (res < 0) {
				printf("Failed to create thread!\n");
				return NULL;
			}
			data->threads.push_back(t);
		}
		printf("%d: Thread yielding %d / %d\n",
				gettid(), data->depth, data->max_depth);
		sched_yield();

		printf("%d: Thread exiting %d / %d\n",
				gettid(), data->depth, data->max_depth);
		data->depth--;
		return NULL;
	}
}

void test_threads()
{
	int x = 666;
	pthread_t t1;
	pthread_t t2;
	int res;
	pthread_mutex_init(&mtx, NULL);

	//printf("*** Testing pthread_create and sched_yield...\n");
	res = pthread_create(&t1, NULL, thread_function1, &x);
	if (res < 0) {
		printf("Failed to create thread!\n");
		return;
	}
	pthread_join(t1, NULL);

	res = pthread_create(&t2, NULL, thread_function2, &x);
	if (res < 0) {
		printf("Failed to create thread!\n");
		return;
	}

	printf("Yielding from main thread, expecting to return to thread2\n");
	// Ride back to thread2 using contested lock
	pthread_mutex_lock(&mtx);
	pthread_mutex_unlock(&mtx);
	printf("After yielding from main thread, looking good!\n");
	// remove the thread
	pthread_join(t2, NULL);

	printf("*** Now testing recursive threads...\n");
	static testdata rdata;
	recursive_function(&rdata);
	// now we have to yield until all the detached children also exit
	printf("*** Yielding until all children are dead!\n");
	while (rdata.depth > 0) sched_yield();

	printf("*** Joining until all children are freed!\n");
	for (auto pt : rdata.threads) pthread_join(pt, NULL);

	auto* cpp_thread = new std::thread(
		[] (int a, long long b, std::string c) -> void {
			printf("Hello from a C++ thread\n");
			assert(a == 1);
			assert(b == 2LL);
			assert(c == std::string("test"));
			printf("C++ thread arguments are OK, yielding...\n");
			std::this_thread::yield();
			printf("C++ thread exiting...\n");
		},
		1, 2L, std::string("test"));
	printf("Returned to main. Yielding back...\n");
	std::this_thread::yield();
	printf("Returned to main. Joining the C++ thread\n");
	cpp_thread->join();
	printf("Deleting the C++ thread\n");
	delete cpp_thread;

	printf("SUCCESS\n");
}
