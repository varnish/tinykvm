/* Syscall-heavy workload microbenchmark guest for TinyKVM x86_64.
 *
 * Measures the cost of the unconditional `mov cr3` reload that the Bug A fix
 * added to the generic syscall-return path in amd64/builtin/interrupts.asm.
 *
 * Build (plain gcc, static):
 *   gcc -static -O2 -ggdb3 -fno-builtin syscall_bench.c -o syscall_bench
 *
 * Exported vmcall entrypoints (all take a 64-bit iteration count):
 *   bench_vmexits(count)            -- raw port-IO vmexit round-trip (baseline;
 *                                      does NOT enter the .vm64_syscall handler)
 *   bench_syscalls(count)           -- real `syscall` instr, getpid(39): the
 *                                      generic path that now reloads CR3
 *   bench_syscalls_touch(count,pgs) -- one getpid + read `pgs` 4K pages of a
 *                                      working set each iteration (models the
 *                                      TLB re-walk a real interpreter pays after
 *                                      a full flush)
 *   bench_touch_only(count,pgs)     -- the touch loop with no syscall (warm-TLB
 *                                      reference for the _touch numbers)
 */
#include <stddef.h>
#include <stdint.h>

/* Raw syscall instruction. NOT the libc wrapper -- glibc caches getpid(), and
 * we specifically need a real `syscall` that traps into LSTAR -> .vm64_syscall
 * -> `out 0,eax` -> host -> (CR3 reload) -> sysret on every call. */
static inline long sys0(long n)
{
	long ret;
	register long rax asm("rax") = n;
	asm volatile("syscall" : "+a"(rax) : : "rcx", "r11", "memory");
	return ret = rax;
}

/* 32 MB working set in .bss; one touched byte per 4 KB page -> up to 8192 pages.
 * Touched once in main() so the pages are present (and CoW-shared) on forks. */
#define WS_PAGES_MAX 8192u
#define PAGE_SIZE    4096u
#define WS_BYTES     ((size_t)WS_PAGES_MAX * PAGE_SIZE)
static volatile unsigned char ws[WS_BYTES];
static volatile unsigned long sink;

int main(int argc, char **argv)
{
	(void)argc; (void)argv;
	for (size_t i = 0; i < WS_BYTES; i += PAGE_SIZE)
		ws[i] = 1;
	return 0;
}

/* Raw vmexit baseline: a single OUT to port 1 (KVM_EXIT_IO), same trick the
 * other guests use. This bypasses the syscall handler entirely. */
__asm__(".global one_vmexit\n"
	".type one_vmexit, function\n"
	"one_vmexit:\n"
	"	out %ax, $1\n"
	"	ret\n");
extern void one_vmexit(void);

__attribute__((used))
void bench_vmexits(long count)
{
	while (count-- > 0)
		one_vmexit();
}

__attribute__((used))
void bench_syscalls(long count)
{
	while (count-- > 0)
		sys0(39); /* getpid: cheap, host-handled, not special-cased */
}

__attribute__((used))
void bench_syscalls_touch(long count, long pages)
{
	if (pages < 0) pages = 0;
	if ((unsigned long)pages > WS_PAGES_MAX) pages = WS_PAGES_MAX;
	while (count-- > 0) {
		sys0(39);
		unsigned long s = 0;
		for (long p = 0; p < pages; p++)
			s += ws[(size_t)p << 12];
		sink += s;
	}
}

__attribute__((used))
void bench_touch_only(long count, long pages)
{
	if (pages < 0) pages = 0;
	if ((unsigned long)pages > WS_PAGES_MAX) pages = WS_PAGES_MAX;
	while (count-- > 0) {
		unsigned long s = 0;
		for (long p = 0; p < pages; p++)
			s += ws[(size_t)p << 12];
		sink += s;
	}
}

/* ---- Bug A correctness probes -------------------------------------------
 * A hostcall (syscall 500) asks the host to fill a guest buffer via
 * copy_to_guest, which CoW-remaps the buffer's page(s) mid-syscall. The guest
 * then reads the buffer back and returns an FNV-1a checksum. With the targeted
 * invalidation the read sees the freshly delivered bytes; without it, the stale
 * (zero) master page. cow_single touches one page (targeted invlpg path);
 * cow_multi spans two pages (sentinel -> CR3 reload path). */
#define HOSTCALL_FILL 500

static inline long sys2(long n, void *a, long b)
{
	long ret;
	register long rax asm("rax") = n;
	register void *rdi asm("rdi") = a;
	register long rsi asm("rsi") = b;
	asm volatile("syscall" : "+a"(rax) : "r"(rdi), "r"(rsi) : "rcx", "r11", "memory");
	return ret = rax;
}

static unsigned fnv1a(volatile unsigned char *p, long n)
{
	unsigned h = 2166136261u;
	for (long i = 0; i < n; i++) { h ^= p[i]; h *= 16777619u; }
	return h;
}

static volatile unsigned char cow_buf[256];
static volatile unsigned char cow_buf_multi[8192];

__attribute__((used))
unsigned cow_single(void)
{
	volatile unsigned char warm = cow_buf[0]; /* cache the (stale) translation */
	(void)warm;
	sys2(HOSTCALL_FILL, (void *)cow_buf, sizeof(cow_buf));
	return fnv1a(cow_buf, sizeof(cow_buf));
}

__attribute__((used))
unsigned cow_multi(void)
{
	for (size_t i = 0; i < sizeof(cow_buf_multi); i += PAGE_SIZE) {
		volatile unsigned char warm = cow_buf_multi[i]; (void)warm;
	}
	sys2(HOSTCALL_FILL, (void *)cow_buf_multi, sizeof(cow_buf_multi));
	return fnv1a(cow_buf_multi, sizeof(cow_buf_multi));
}

/* Required no-op entrypoint so the generic bench harness can also load this. */
__attribute__((used))
void bench(void) {}
