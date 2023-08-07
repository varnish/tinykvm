#include <stdarg.h>
#include <stdio.h>
#define ARCH_SET_FS   0x1002
#define ARCH_GET_FS   0x1003
extern void arch_prctl(unsigned, ...);
extern void NimMain();
extern long write(int, const void*, size_t);
extern void _exit(int);

static long stored_fs;

static inline long get_fs()
{
	long fs;
	arch_prctl(ARCH_GET_FS, &fs);
	return fs;
}

static int safeprint(const char* fmt, ...)
{
	char buffer[4096];

	va_list va;
	va_start(va, fmt);
	int len = vsnprintf(buffer, sizeof(buffer), fmt, va);
	va_end(va);

	return write(1, buffer, len);
}

void restore_fs()
{
	// XXX: Don't try to print here. WONT WORK!
	long old_fs = get_fs();
	arch_prctl(ARCH_SET_FS, stored_fs);
	safeprint("Restored FS 0x%lX\n", stored_fs);
	stored_fs = old_fs;
}

void quick_exit(int code)
{
	stored_fs = get_fs();
	_exit(code);
}

int main()
{
	// Provoke proper stdio
	fflush(stdout);
	stored_fs = get_fs();

	NimMain();
	_exit(0);
}
