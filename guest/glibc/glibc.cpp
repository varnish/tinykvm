#include <cassert>
#include <malloc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <cstdlib>
static void test_threads();
extern "C" int gettid();

static int threads_test_suite_ok = 0;

/* ------------------------------------------------------------------------
 * Snapshot-ordering workload.
 *
 * g_buffer is a large buffer that lives in BSS, so it is part of the booted
 * snapshot image. main() touches every page (making it resident in the
 * snapshot file), and test() then streams over it in a FIXED, SCATTERED page
 * order (g_order). Because the access order is decorrelated from the buffer's
 * virtual/physical layout, the on-disk page ordering decides whether the cold
 * page faults during test() become one sequential file read (fault-order
 * snapshot) or thousands of random reads (no-order snapshot).
 * ------------------------------------------------------------------------ */
static constexpr size_t WS_PAGE  = 4096;
static constexpr size_t WS_BYTES = 128UL * 1024 * 1024; /* 128 MiB working set */
static constexpr size_t WS_PAGES = WS_BYTES / WS_PAGE;

static uint8_t  g_buffer[WS_BYTES];
static uint32_t g_order[WS_PAGES];

/* Deterministic Fisher-Yates shuffle (fixed seed) so that the fault-order
   capture run and every replay run touch the pages in the identical order. */
static void build_workset()
{
	for (size_t i = 0; i < WS_PAGES; i++)
		g_order[i] = (uint32_t)i;

	uint64_t s = 0x9E3779B97F4A7C15ULL;
	for (size_t i = WS_PAGES - 1; i > 0; i--) {
		s = s * 6364136223846793005ULL + 1442695040888963407ULL;
		const size_t j = (size_t)((s >> 33) % (i + 1));
		const uint32_t t = g_order[i]; g_order[i] = g_order[j]; g_order[j] = t;
	}
	/* Make every page resident in the snapshot with a non-zero, page-unique
	   value so the file is not sparse for this region. */
	for (size_t i = 0; i < WS_PAGES; i++)
		g_buffer[i * WS_PAGE] = (uint8_t)(1 + (i & 0xFF));
}

int main()
{
	char* hello = (char *)malloc(14);
	strcpy(hello, "Hello World!\n");
	printf("%.*s", 13, hello);

	build_workset();
	test_threads();

	// Prevent global destructors
	std::quick_exit(0);
}

/* The replayed request: stream the working set in scattered page order. The
   returned checksum keeps the reads from being optimised away. */
extern "C" __attribute__((used))
uint64_t test()
{
	uint64_t sum = 0;
	for (size_t i = 0; i < WS_PAGES; i++)
		sum += g_buffer[(size_t)g_order[i] * WS_PAGE];
	return sum;
}

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
	threads_test_suite_ok = 1;
}

static std::vector<int> data = {1, 2, 3, 4, 5};

struct MyStruct {
	int a;
	float b;
	char c;
};
extern "C" void my_backend(const char* arg1, MyStruct* arg2, int arg3)
{
	printf("Hello from my_backend! arg1=%s, arg2={a=%d, b=%f, c='%c'}, arg3=%d\n",
		arg1, arg2->a, arg2->b, arg2->c, arg3);
	printf("State of global data: %d %d %d %d %d  Size: %zu\n",
		data[0], data[1], data[2], data[3], data[4], data.size());
}
