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

int main(int argc, char** argv)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <guest.elf>\n", argv[0]);
		return 1;
	}
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
