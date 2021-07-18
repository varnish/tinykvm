#include <cstdio>

void do_kassert(bool pred, const char* text, int line, const char* file, const char* function)
{
	if (pred) return;
	fprintf(stderr, "%s:%d assertion failed in function %s: %s\n",
		file, line, function, text);
	std::abort();
}

#define KASSERT(pred) \
	do_kassert(pred, #pred, __LINE__, __FILE__, __FUNCTION__)
