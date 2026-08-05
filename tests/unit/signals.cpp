#include <catch2/catch_test_macros.hpp>

#include <csignal>
#include <string>
#include <utility>
#include <vector>
#include <tinykvm/machine.hpp>

/* Guest signal-handler delivery on AMD64. Delivery replaces the whole
   register frame and sysrets into the handler through a kernel trampoline;
   the handler returns into a usermode rt_sigreturn stub that pops the
   interrupted frame. Mirrors tests/unit/arm64_signals.cpp so the two
   backends stay behaviourally identical. */

extern std::pair<std::string, std::vector<uint8_t>>
	build_and_load(const std::string& code, const std::string& args);

static const uint64_t MAX_MEMORY = 64ul << 20; /* 64MB */
static const uint64_t MAX_COWMEM = 8ul << 20; /* 8MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

/* Idempotent, so a single filtered test case still runs standalone. */
static void init_kvm()
{
	static const bool once = [] { tinykvm::Machine::init(); return true; }();
	(void)once;
}

TEST_CASE("Signal handler runs and resumes", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int got = 0;
static volatile int got_sig = -1;
static void handler(int s) { got = 1; got_sig = s; }
int main() {
	if (signal(SIGUSR1, handler) == SIG_ERR) return 1;
	raise(SIGUSR1);
	if (!got) return 2;
	if (got_sig != SIGUSR1) return 3;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Signal preserves interrupted context", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile long scratch = 0;
static void handler(int s) { (void)s; scratch = 0xDEADBEEF; }
int main() {
	signal(SIGUSR1, handler);
	volatile long a = 11, b = 31, c = 0;
	for (long i = 0; i < 1000; i++) c += a * b;
	int rc = raise(SIGUSR1);
	c += a + b;
	if (rc != 0) return 1;
	if (scratch != (long)0xDEADBEEF) return 2;
	if (c != 341042) return 3;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Repeated signal delivery", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int count = 0;
static void handler(int s) { (void)s; count++; }
int main() {
	signal(SIGUSR1, handler);
	for (int i = 0; i < 1000; i++) raise(SIGUSR1);
	return count == 1000 ? 666 : count;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("SIG_IGN is dropped", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	signal(SIGUSR1, SIG_IGN);
	if (raise(SIGUSR1) != 0) return 1;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Signal runs on alternate stack", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <stdint.h>
#define ALTSZ (64 * 1024)
static char altbuf[ALTSZ] __attribute__((aligned(16)));
static volatile int on_alt = 0;
static void handler(int s) {
	(void)s;
	uintptr_t fp = (uintptr_t)__builtin_frame_address(0);
	uintptr_t lo = (uintptr_t)altbuf;
	uintptr_t hi = lo + sizeof(altbuf);
	on_alt = (fp >= lo && fp < hi);
}
int main() {
	stack_t ss;
	memset(&ss, 0, sizeof ss);
	ss.ss_sp = altbuf;
	ss.ss_size = sizeof(altbuf);
	if (sigaltstack(&ss, 0) != 0) return 1;
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	sa.sa_flags = SA_ONSTACK;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 2;
	raise(SIGUSR1);
	return on_alt ? 666 : 3;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Unhandled fatal signal terminates VM", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	raise(SIGUSR1);
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 128 + SIGUSR1);
}

TEST_CASE("Signal delivered to a worker thread", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <pthread.h>
#include <signal.h>
static volatile int got = 0;
static void handler(int s) { (void)s; got++; }
static void* worker(void* arg) {
	(void)arg;
	for (int i = 0; i < 50; i++) raise(SIGUSR1);
	return (void*)(unsigned long)got;
}
int main() {
	signal(SIGUSR1, handler);
	pthread_t t;
	if (pthread_create(&t, 0, worker, 0) != 0) return 1;
	void* ret = 0;
	if (pthread_join(t, &ret) != 0) return 2;
	if ((long)(unsigned long)ret != 50) return 3;
	if (got != 50) return 4;
	return 666;
})M", "-pthread");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Nested signal delivery preserves outer frame", "[Signals]")
{
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int order = 0;
static void h2(int s) { (void)s; order = order * 10 + 2; }
static void h1(int s) {
	(void)s;
	order = order * 10 + 1;
	raise(SIGUSR2);
	order = order * 10 + 1;
}
int main() {
	signal(SIGUSR1, h1);
	signal(SIGUSR2, h2);
	raise(SIGUSR1);
	return order == 121 ? 666 : order;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	if (getenv("VERBOSE")) {
		machine.set_verbose_system_calls(true);
		machine.set_verbose_thread_syscalls(true);
	}
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Signal handler sees a clean flags state", "[Signals]")
{
	/* Delivery loads RFLAGS from R11 through sysret. DF must be clear on
	   entry to a SysV function -- a handler doing memcpy/memset with DF set
	   would copy backwards -- and AC must be clear or a stray STAC leaks
	   SMAP-bypass into usermode. */
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
#include <string.h>
static volatile unsigned long flags = 0;
static volatile int copied_forwards = 0;
static void handler(int s) {
	(void)s;
	unsigned long f;
	__asm__ volatile("pushfq; pop %0" : "=r"(f));
	flags = f;
	char src[8] = {1,2,3,4,5,6,7,8};
	char dst[8] = {0};
	memcpy(dst, src, sizeof(dst));
	copied_forwards = (dst[0] == 1 && dst[7] == 8);
}
int main() {
	signal(SIGUSR1, handler);
	/* Set DF and AC before raising: neither may survive into the handler. */
	__asm__ volatile("std");
	raise(SIGUSR1);
	__asm__ volatile("cld");
	if (flags & (1UL << 10)) return 1; /* DF */
	if (flags & (1UL << 18)) return 2; /* AC */
	if (!(flags & (1UL << 9))) return 3; /* IF must be set */
	if (!copied_forwards) return 4;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Non-canonical handler falls back to terminating", "[Signals]")
{
	/* Delivery sysrets straight to the handler address. A non-canonical one
	   would #GP inside the ring-0 trampoline instead of merely killing the
	   guest, so such a handler counts as no handler at all. */
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
int main() {
	signal(SIGUSR1, (void(*)(int))0x8000000000000000UL);
	raise(SIGUSR1);
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 128 + SIGUSR1);
}

/* Shared preamble for the SA_SIGINFO tests: raising through a bare `syscall`
   rather than raise() keeps libc off the register state, so the test can say
   exactly what the interrupted context was and check the frame against it. */
static const std::string SIGINFO_PRELUDE = R"M(
#define _GNU_SOURCE
#include <signal.h>
#include <string.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/ucontext.h>
#include <unistd.h>

static long g_pid, g_tid;
static void resolve_ids(void) {
	g_pid = syscall(SYS_getpid);
	g_tid = syscall(SYS_gettid);
}
)M";

TEST_CASE("SA_SIGINFO handler receives a valid siginfo", "[Signals]")
{
	/* Go's runtime.sighandler dereferences info->si_code before anything
	   else, so a null siginfo faults on the very first signal. It also
	   branches on SI_TKILL to tell a raised signal from a fault. */
	init_kvm();
	const auto [program, binary] = build_and_load(SIGINFO_PRELUDE + R"M(
static volatile int v_signo = -1, v_code = 1, v_ptr_ok = 0, v_uc_ok = 0;
static void handler(int s, siginfo_t* si, void* uc) {
	(void)s;
	v_ptr_ok = (si != 0);
	v_uc_ok  = (uc != 0);
	if (si) { v_signo = si->si_signo; v_code = si->si_code; }
}
int main() {
	resolve_ids();
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;
	syscall(SYS_tgkill, g_pid, g_tid, SIGUSR1);
	if (!v_ptr_ok) return 2;
	if (!v_uc_ok) return 3;
	if (v_signo != SIGUSR1) return 4;
	if (v_code != -6 /* SI_TKILL */) return 5;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("ucontext reports the interrupted register state", "[Signals]")
{
	/* The frame must describe the *usermode* context, not the kernel stub the
	   trap was taken in: RIP is the instruction after the syscall and RSP the
	   guest's own stack, with the stub's pushed TLB slot undone. */
	init_kvm();
	const auto [program, binary] = build_and_load(SIGINFO_PRELUDE + R"M(
static volatile uint64_t v_rip = 0, v_rsp = 0, v_cs = 0, v_ss = 0, v_efl = 0;
static volatile uint64_t v_frame = 0;
static volatile void* v_fpregs = 0;
static void handler(int s, siginfo_t* si, void* ucv) {
	(void)s; (void)si;
	ucontext_t* uc = (ucontext_t*)ucv;
	v_rip = uc->uc_mcontext.gregs[REG_RIP];
	v_rsp = uc->uc_mcontext.gregs[REG_RSP];
	v_efl = uc->uc_mcontext.gregs[REG_EFL];
	v_cs  = uc->uc_mcontext.gregs[REG_CSGSFS] & 0xFFFF;
	v_ss  = (uc->uc_mcontext.gregs[REG_CSGSFS] >> 48) & 0xFFFF;
	v_fpregs = uc->uc_mcontext.fpregs;
	/* The ucontext sits one qword above the frame base, which is what RSP was
	   on entry -- so this recovers the entry RSP exactly, without depending on
	   whatever prologue the compiler emitted for this handler. */
	v_frame = (uint64_t)ucv - 8;
}
int main() {
	resolve_ids();
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;

	uint64_t after_rip = 0, before_rsp = 0, before_efl = 0;
	register long a __asm__("rax") = SYS_tgkill;
	register long di __asm__("rdi") = g_pid;
	register long si __asm__("rsi") = g_tid;
	register long dx __asm__("rdx") = SIGUSR1;
	__asm__ volatile(
		"pushfq\n\t"
		"popq %2\n\t"
		"mov %%rsp, %1\n\t"
		"syscall\n\t"
		"1:\n\t"
		"lea 1b(%%rip), %0\n\t"
		: "=&r"(after_rip), "=&r"(before_rsp), "=&r"(before_efl), "+r"(a)
		: "r"(di), "r"(si), "r"(dx)
		: "rcx", "r11", "memory");

	if (v_rip != after_rip) return 2;
	if (v_rsp != before_rsp) return 3;
	if (v_cs != 0x2B) return 4;
	if (v_ss != 0x23) return 5;
	/* The reported flags are the guest's own, not a sanitised constant.
	   RF always reads back as 0 through pushfq, so ignore just that bit. */
	if (((v_efl ^ before_efl) & ~(1UL << 16)) != 0) return 6;
	if (v_fpregs == 0) return 7;              /* must point at a real FXSAVE area */
	/* SysV: RSP+8 must be 16-byte aligned on entry to the handler, or its
	   first movaps faults. */
	if (((v_frame + 8) & 0xF) != 0) return 8;
	/* And the frame must sit below the interrupted stack, clear of both the
	   128-byte red zone and the syscall stub's TLB slot just under RSP. */
	if (v_frame >= before_rsp - 128) return 9;
	if (v_frame < before_rsp - 4096) return 10;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Handler edits to the ucontext take effect on return", "[Signals]")
{
	/* rt_sigreturn must resume from the ucontext the handler was given, not
	   from the frame captured at delivery. This is how Go's async preemption
	   splices a call into the interrupted thread, and how siglongjmp works. */
	init_kvm();
	const auto [program, binary] = build_and_load(SIGINFO_PRELUDE + R"M(
static void handler(int s, siginfo_t* si, void* ucv) {
	(void)s; (void)si;
	ucontext_t* uc = (ucontext_t*)ucv;
	uc->uc_mcontext.gregs[REG_R14] = 0xABCDEF;
}
int main() {
	resolve_ids();
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;

	uint64_t r14_after = 0;
	register long a __asm__("rax") = SYS_tgkill;
	register long di __asm__("rdi") = g_pid;
	register long si __asm__("rsi") = g_tid;
	register long dx __asm__("rdx") = SIGUSR1;
	__asm__ volatile(
		"xor %%r14, %%r14\n\t"
		"syscall\n\t"
		"mov %%r14, %0\n\t"
		: "=&r"(r14_after), "+r"(a)
		: "r"(di), "r"(si), "r"(dx)
		: "rcx", "r11", "r14", "memory");

	return r14_after == 0xABCDEF ? 666 : 2;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Vector registers survive a handler that clobbers them", "[Signals]")
{
	/* The frame carries an FXSAVE image and sigreturn feeds it back through
	   KVM_SET_FPU, so a handler using SSE -- which is every handler that
	   calls memcpy -- does not corrupt the interrupted context. */
	init_kvm();
	const auto [program, binary] = build_and_load(SIGINFO_PRELUDE + R"M(
static double g_clobber = 7.5;
static void handler(int s) {
	(void)s;
	/* Deliberately a non-zero value. Zeroing every vector register instead
	   would put SSE back in its XSAVE init state, which KVM_GET_FPU and
	   KVM_SET_FPU cannot see or repair -- they carry only the legacy FXSAVE
	   area, not the XSAVE header. See save_fpu_state() in signals.cpp. */
	__asm__ volatile("movsd %0, %%xmm3" :: "m"(g_clobber) : "xmm3");
}
int main() {
	resolve_ids();
	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_handler = handler;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 1;

	double in = 3.25, out = 0.0;
	register long a __asm__("rax") = SYS_tgkill;
	register long di __asm__("rdi") = g_pid;
	register long si __asm__("rsi") = g_tid;
	register long dx __asm__("rdx") = SIGUSR1;
	__asm__ volatile(
		"movsd %2, %%xmm3\n\t"
		"syscall\n\t"
		"movsd %%xmm3, %0\n\t"
		: "=m"(out), "+r"(a)
		: "m"(in), "r"(di), "r"(si), "r"(dx)
		: "rcx", "r11", "xmm3", "memory");

	return out == 3.25 ? 666 : 2;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("sigaltstack reports the previously installed stack", "[Signals]")
{
	/* sigaltstack(NULL, &old) is how a runtime decides whether to claim the
	   alternate stack; the Go runtime does it on every thread start. Leaving
	   the guest's buffer untouched handed it uninitialised stack memory. */
	init_kvm();
	const auto [program, binary] = build_and_load(SIGINFO_PRELUDE + R"M(
#define ALTSZ (64 * 1024)
static char altbuf[ALTSZ] __attribute__((aligned(16)));
static volatile uint64_t v_uc_ss_sp = 1;
static volatile uint64_t v_uc_ss_size = 0;
static void handler(int s, siginfo_t* si, void* ucv) {
	(void)s; (void)si;
	ucontext_t* uc = (ucontext_t*)ucv;
	v_uc_ss_sp = (uint64_t)uc->uc_stack.ss_sp;
	v_uc_ss_size = uc->uc_stack.ss_size;
}
int main() {
	resolve_ids();
	stack_t old;
	memset(&old, 0xAA, sizeof old);
	if (sigaltstack(0, &old) != 0) return 1;
	/* Nothing installed yet: must read back as disabled, not as garbage. */
	if (!(old.ss_flags & SS_DISABLE)) return 2;

	stack_t ss;
	memset(&ss, 0, sizeof ss);
	ss.ss_sp = altbuf;
	ss.ss_size = sizeof(altbuf);
	if (sigaltstack(&ss, 0) != 0) return 3;

	memset(&old, 0xAA, sizeof old);
	if (sigaltstack(0, &old) != 0) return 4;
	if (old.ss_sp != altbuf) return 5;
	if (old.ss_size != sizeof(altbuf)) return 6;
	if (old.ss_flags & SS_DISABLE) return 7;

	struct sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.sa_sigaction = handler;
	sa.sa_flags = SA_SIGINFO | SA_ONSTACK;
	if (sigaction(SIGUSR1, &sa, 0) != 0) return 8;
	syscall(SYS_tgkill, g_pid, g_tid, SIGUSR1);

	/* And the frame's uc_stack describes that same alternate stack. */
	if (v_uc_ss_sp != (uint64_t)altbuf) return 9;
	if (v_uc_ss_size != sizeof(altbuf)) return 10;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Handler returns through the guest's own sa_restorer", "[Signals]")
{
	/* x86-64 has no kernel-supplied restorer, so Linux uses the one the libc
	   passes. Honouring it keeps unwinders working: libgcc recognises a
	   signal frame by matching the restorer's exact instruction bytes. */
	init_kvm();
	const auto [program, binary] = build_and_load(SIGINFO_PRELUDE + R"M(
#define SA_RESTORER 0x04000000
struct kernel_sigaction {
	void*    handler;
	unsigned long flags;
	void*    restorer;
	unsigned long mask;
};
static volatile int v_hit = 0;
static volatile uint64_t v_pretcode = 0;
extern void my_restorer(void);
__asm__(".globl my_restorer\n"
	"my_restorer:\n"
	"  movq $15, %rax\n"   /* SYS_rt_sigreturn */
	"  syscall\n"
	"  ud2\n");
static void handler(int s, siginfo_t* si, void* ucv) {
	(void)s; (void)si;
	/* pretcode sits one qword below the ucontext. */
	v_pretcode = *(uint64_t*)((char*)ucv - 8);
	v_hit++;
}
int main() {
	resolve_ids();
	struct kernel_sigaction sa;
	memset(&sa, 0, sizeof sa);
	sa.handler = (void*)handler;
	sa.flags = SA_SIGINFO | SA_RESTORER;
	sa.restorer = (void*)my_restorer;
	if (syscall(SYS_rt_sigaction, SIGUSR1, &sa, 0, 8) != 0) return 1;
	syscall(SYS_tgkill, g_pid, g_tid, SIGUSR1);
	if (v_hit != 1) return 2;
	if (v_pretcode != (uint64_t)my_restorer) return 3;
	return 666;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);

	REQUIRE(machine.return_value() == 666);
}

TEST_CASE("Signal delivery inside a CoW fork", "[Signals]")
{
	/* The delivery path writes the handler's return address into the guest
	   stack, which in a fork means materializing a private page. The kernel
	   trampoline reloads CR3 for exactly this reason: it bypasses the
	   syscall stub epilogue that would otherwise invalidate the stale
	   read-only translation. */
	init_kvm();
	const auto [program, binary] = build_and_load(R"M(
#include <signal.h>
static volatile int got = 0;
static void handler(int s) { (void)s; got++; }
int main() {
	signal(SIGUSR1, handler);
}
extern long deliver() {
	got = 0;
	for (int i = 0; i < 100; i++) raise(SIGUSR1);
	return got;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"signals"}, env);
	machine.run(8.0f);
	machine.prepare_copy_on_write();

	const auto funcaddr = machine.address_of("deliver");
	REQUIRE(funcaddr != 0x0);

	tinykvm::Machine fork { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	} };
	fork.timed_vmcall(funcaddr, 8.0f);
	REQUIRE(fork.return_value() == 100);

	/* And again after a reset, since reset_to() restores the master's
	   handlers and drops the fork's private pages. */
	fork.reset_to(machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	});
	fork.timed_vmcall(funcaddr, 8.0f);
	REQUIRE(fork.return_value() == 100);
}
