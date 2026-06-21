/* Microbenchmark for the per-syscall CR3-reload cost (Bug A fix).
 *
 * Forks a guest from a CoW master and repeatedly calls the guest's
 * bench_* entrypoints, reporting nanoseconds per operation. Run the same
 * binary against a library built WITH the reload and one built WITHOUT it
 * (see scripts/syscall_bench.sh) and diff the RESULT lines.
 */
#include <tinykvm/machine.hpp>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <algorithm>
#include <vector>
#include <sched.h>
#include "load_file.hpp"

#define GUEST_MEMORY   0x40000000   /* 1 GB */
#define GUEST_COW_MEM  (16UL << 20) /* 16 MB CoW working pages */

static std::vector<uint8_t> binary;

static inline uint64_t now_ns()
{
	timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (uint64_t)t.tv_sec * 1000000000ULL + t.tv_nsec;
}

/* Run vmcall(addr, args...) `trials` times over `count` ops each; return the
 * smallest observed ns/op (min filters scheduler/turbo noise). */
template <typename... Args>
static double bench_op(tinykvm::Machine& vm, uint64_t addr,
	uint64_t count, int trials, Args... args)
{
	double best = 1e30;
	for (int t = 0; t < trials; t++) {
		asm volatile("" ::: "memory");
		uint64_t t0 = now_ns();
		asm volatile("" ::: "memory");
		vm.vmcall(addr, (long)count, args...);
		asm volatile("" ::: "memory");
		uint64_t t1 = now_ns();
		double ns = double(t1 - t0) / double(count);
		best = std::min(best, ns);
	}
	return best;
}

/* Host pattern the HOSTCALL_FILL handler writes into the guest buffer. */
static uint8_t fill_byte(size_t i) { return (uint8_t)(0xA5 ^ (i * 7 + 3)); }
static unsigned host_fnv1a(size_t len) {
	unsigned h = 2166136261u;
	for (size_t i = 0; i < len; i++) { h ^= fill_byte(i); h *= 16777619u; }
	return h;
}

/* syscall 500: copy a known pattern into [arg0, arg0+arg1). This runs mid-
   vmcall and CoW-remaps the destination page(s) on the forked VM — the exact
   condition that left guest reads stale before the targeted-invalidation fix. */
static void hostcall_fill(tinykvm::vCPU& cpu)
{
	auto& regs = cpu.registers();
	const uint64_t addr = regs.sysarg(0);
	const uint64_t len  = regs.sysarg(1);
	std::vector<uint8_t> pat(len);
	for (uint64_t i = 0; i < len; i++) pat[i] = fill_byte(i);
	cpu.machine().copy_to_guest(addr, pat.data(), len);
	regs.sysret() = 0;
	cpu.set_registers(regs);
}

static int run_correctness(const tinykvm::Machine& master,
	const tinykvm::MachineOptions& options)
{
	tinykvm::Machine::install_syscall_handler(500, hostcall_fill);
	struct Case { const char* name; const char* fn; unsigned want; };
	const Case cases[] = {
		{ "cow_single (1 page -> targeted invlpg)", "cow_single", host_fnv1a(256) },
		{ "cow_multi  (2 pages -> sentinel reload)", "cow_multi", host_fnv1a(8192) },
		/* Corruption regression: a CoW write-fault sets the pending TLB signal,
		   then mmap traps on the non-slot port-0 path; the host must NOT write
		   the signal over the live [rsp]. Returns 0xC0FFEE iff [rsp] survived. */
		{ "mmap_after_cow (port-0 [rsp] not clobbered)", "mmap_after_cow", 0xC0FFEEu },
	};
	int failures = 0;
	for (const auto& c : cases) {
		/* Fresh fork each case, mirroring how a pooled worker is recycled. */
		tinykvm::Machine vm { master, options };
		const uint64_t addr = vm.address_of(c.fn);
		unsigned got = 0;
		const char* err = nullptr;
		try {
			vm.vmcall(addr);
			got = (unsigned)vm.return_value();
		} catch (const std::exception& e) {
			err = e.what(); /* a crash/corruption surfaces as a MachineException */
		}
		const bool ok = (!err && got == c.want);
		failures += !ok;
		if (err)
			printf("%-42s threw: %s  FAIL\n", c.name, err);
		else
			printf("%-42s got=0x%08X want=0x%08X  %s\n",
				c.name, got, c.want, ok ? "PASS" : "FAIL");
	}
	printf("%s\n", failures ? "CORRECTNESS: FAIL" : "CORRECTNESS: PASS");
	return failures ? 1 : 0;
}

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <guest.elf> [verify]\n", argv[0]);
		return 1;
	}
	const bool verify_mode = (argc >= 3 && std::string(argv[2]) == "verify");
	/* Pin to one CPU to reduce migration noise. */
	cpu_set_t set; CPU_ZERO(&set); CPU_SET(1, &set);
	sched_setaffinity(0, sizeof(set), &set);

	binary = load_file(argv[1]);
	tinykvm::Machine::init();

	const tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_COW_MEM,
		.verbose_loader = false,
	};
	tinykvm::Machine master {binary, options};
	master.setup_linux({"syscall_bench"}, {"LC_ALL=C", "USER=root"});
	master.run();
	master.prepare_copy_on_write();

	if (verify_mode)
		return run_correctness(master, options);

	const uint64_t a_vmexit  = master.address_of("bench_vmexits");
	const uint64_t a_syscall = master.address_of("bench_syscalls");
	const uint64_t a_touch   = master.address_of("bench_syscalls_touch");
	const uint64_t a_only    = master.address_of("bench_touch_only");
	if (!a_vmexit || !a_syscall || !a_touch || !a_only) {
		fprintf(stderr, "Missing bench symbols in guest "
			"(vmexits=%lx syscalls=%lx touch=%lx only=%lx)\n",
			a_vmexit, a_syscall, a_touch, a_only);
		return 1;
	}

	tinykvm::Machine vm {master, options};

	/* Warmup: fault in code/stack and let frequency ramp. */
	vm.vmcall(a_vmexit,  (long)200000);
	vm.vmcall(a_syscall, (long)200000);
	vm.vmcall(a_touch,   (long)2000, (long)256);

	const int    TRIALS    = 7;
	const uint64_t TIGHT   = 5000000;  /* tight loops */
	const uint64_t TOUCHN  = 1000000;  /* touch loops (more work/iter) */

	double ns_vmexit  = bench_op(vm, a_vmexit,  TIGHT, TRIALS);
	double ns_syscall = bench_op(vm, a_syscall, TIGHT, TRIALS);

	printf("RESULT vmexit_ns %.2f\n", ns_vmexit);
	printf("RESULT syscall_ns %.2f\n", ns_syscall);
	fflush(stdout);

	static const long page_sweep[] = {0,1,2,4,8,16,32,64,128,256,512,1024,2048,4096};
	for (long pages : page_sweep) {
		double ns_only  = bench_op(vm, a_only,  TOUCHN, TRIALS, pages);
		double ns_both  = bench_op(vm, a_touch, TOUCHN, TRIALS, pages);
		printf("RESULT touch pages=%ld only_ns=%.2f syscall_touch_ns=%.2f\n",
			pages, ns_only, ns_both);
		fflush(stdout);
	}
	return 0;
}
