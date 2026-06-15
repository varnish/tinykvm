/**
 * ARM64 fork/CoW micro-benchmark.
 *
 * Purpose: quantify the per-fork costs in the "warm fork from master" model and
 * empirically settle whether read-access tracking (Option B for get_accessed_pages)
 * could ever help fork-prefetch on this backend.
 *
 * In this model guest memory is shared from the master copy-on-write: a forked
 * guest's *reads* hit resident read-only master pages and never fault, while its
 * *writes* take a CoW permission fault (the only data abort the backend handles).
 * So the only prefetchable per-fork cost is the write working set -- which is what
 * get_accessed_pages already reports. This bench shows read faults == 0 and measures
 * what write-prefetch (Option A's payoff) actually saves.
 *
 * Requires /dev/kvm on an AArch64 host.
 */
#include <tinykvm/arm64/memory_layout.hpp>
#include <tinykvm/machine.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <optional>
#include <utility>
#include <vector>

static constexpr uint64_t MAX_MEMORY = 64ULL << 20;
static constexpr uint64_t CODE_ADDR  = 0x100000;
static constexpr uint64_t STACK_ADDR = 0x180000;
static constexpr uint64_t READ_BASE  = 0x400000; // 4 MiB
static constexpr uint64_t WRITE_BASE  = 0x800000; // 8 MiB
static constexpr uint64_t STRIDE     = 4096;

// Verified via the system assembler (objdump-confirmed); see commit notes.
// x1=read_base x2=read_count x3=write_base x4=write_count x5=stride x6=stop_mmio
static const std::array<uint32_t, 12> guest {
	0xB40000A2, // cbz   x2, +0x14   (read loop)
	0xF9400029, // ldr   x9, [x1]
	0x8B050021, // add   x1, x1, x5
	0xD1000442, // sub   x2, x2, #1
	0x17FFFFFC, // b     -0x10
	0xB40000A4, // cbz   x4, +0x14   (write loop)
	0xF9000067, // str   x7, [x3]
	0x8B050063, // add   x3, x3, x5
	0xD1000484, // sub   x4, x4, #1
	0x17FFFFFC, // b     -0x10
	0xF90000DF, // str   xzr, [x6]   (STOP MMIO)
	0x14000000, // b     .
};

static uint64_t now_ns()
{
	struct timespec ts;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	return uint64_t(ts.tv_sec) * 1'000'000'000ULL + uint64_t(ts.tv_nsec);
}

struct Stats {
	size_t count = 0;
	double avg = 0, p50 = 0, p99 = 0;
};

static Stats stats_of(std::vector<uint64_t> v)
{
	Stats s;
	s.count = v.size();
	if (v.empty())
		return s;
	std::sort(v.begin(), v.end());
	uint64_t sum = 0;
	for (auto x : v) sum += x;
	s.avg = double(sum) / v.size();
	s.p50 = v[v.size() / 2];
	s.p99 = v[(v.size() * 99) / 100];
	return s;
}

static void set_regs(tinykvm::Machine& m, uint64_t R, uint64_t W)
{
	auto regs = m.registers();
	regs.pc = CODE_ADDR;
	regs.sp = STACK_ADDR;
	regs.pstate = 0x3c0;
	regs.regs[1] = READ_BASE;
	regs.regs[2] = R;
	regs.regs[3] = WRITE_BASE;
	regs.regs[4] = W;
	regs.regs[5] = STRIDE;
	regs.regs[6] = tinykvm::ARM64_STOP_MMIO_ADDR;
	regs.regs[7] = 0xDEADBEEFu;
	m.set_registers(regs);
}

// write_set: the accessed set harvested from a warmup fork; prefetched
// (batch pre-CoW) into each fork before its run when non-null.
static void run_config(const char* name, tinykvm::Machine& master,
	const tinykvm::MachineOptions& options, uint64_t R, uint64_t W,
	const std::vector<std::pair<uint64_t, uint64_t>>* write_set,
	bool use_reset, size_t iters)
{
	std::vector<uint64_t> fork_ns, prefetch_ns, run_ns, pf_ns;
	size_t last_accessed = 0;

	// The steady per-agent harness keeps one fork and fast-resets it between
	// runs; the fresh-fork mode measures full construction cost for contrast.
	std::optional<tinykvm::Machine> reset_fork;
	if (use_reset) {
		reset_fork.emplace(master, options);
		reset_fork->set_profiling(true);
	}

	for (size_t i = 0; i < iters; i++) {
		std::optional<tinykvm::Machine> fresh_fork;
		// The reset fork's profiler accumulates across iterations; only the
		// samples recorded after this point belong to this iteration.
		const size_t pf_seen = use_reset
			? reset_fork->profiling()->times.at(tinykvm::MachineProfiling::PageFault).size()
			: 0;
		const uint64_t t0 = now_ns();
		if (use_reset)
			reset_fork->reset_to(master, options);
		else
			fresh_fork.emplace(master, options);
		tinykvm::Machine& fork = use_reset ? *reset_fork : *fresh_fork;
		fork_ns.push_back(now_ns() - t0);
		fork.set_profiling(true);

		if (write_set != nullptr) {
			const uint64_t t1 = now_ns();
			fork.prefetch_pages(*write_set);
			prefetch_ns.push_back(now_ns() - t1);
		}

		set_regs(fork, R, W);
		const uint64_t t2 = now_ns();
		fork.run(2.0f);
		run_ns.push_back(now_ns() - t2);

		// Aggregate this iteration's page-fault samples.
		const auto& samples = fork.profiling()->times.at(tinykvm::MachineProfiling::PageFault);
		pf_ns.insert(pf_ns.end(), samples.begin() + pf_seen, samples.end());
		last_accessed = fork.get_accessed_pages().size();
	}

	const Stats pf = stats_of(pf_ns);
	const Stats fk = stats_of(fork_ns);
	const Stats rn = stats_of(run_ns);
	const Stats pre = stats_of(prefetch_ns);

	std::printf("%-22s R=%-4lu W=%-4lu pf=%s | faults/it=%6.1f  pf_p99=%6.0fns  %s/it=%7.1fus  run/it=%7.1fus  prefetch/it=%7.1fus  accessed=%zu\n",
		name, (unsigned long)R, (unsigned long)W, write_set ? "yes" : "no ",
		double(pf.count) / iters, pf.p99,
		use_reset ? "reset" : "fork",
		fk.avg / 1000.0,
		rn.avg / 1000.0,
		write_set ? pre.avg / 1000.0 : 0.0,
		last_accessed);
}

int main()
{
	try {
		tinykvm::Machine::init();

		const std::vector<uint8_t> empty_binary;
		const tinykvm::MachineOptions options {
			.max_mem = MAX_MEMORY,
			.max_cow_mem = 32u << 20,
			.split_hugepages = true,
		};

		tinykvm::Machine master {empty_binary, options};
		master.copy_to_guest(CODE_ADDR, guest.data(), guest.size() * sizeof(guest[0]));
		master.prepare_copy_on_write(options.max_cow_mem);

		// Warmup fork: run the workload once and harvest its write working
		// set; the prefetched configs below replay this set into every fork.
		std::vector<std::pair<uint64_t, uint64_t>> write_set;
		{
			tinykvm::Machine warmup {master, options};
			set_regs(warmup, 256, 256);
			warmup.run(2.0f);
			write_set = warmup.get_accessed_pages();
		}
		std::printf("Warmup fork write set: %zu ranges\n", write_set.size());

		constexpr size_t ITERS = 300;
		std::printf("ARM64 warm-fork micro-benchmark (%zu iterations/config)\n", ITERS);
		std::printf("-----------------------------------------------------------------------------\n");
		// A: reads only -> expect ZERO page faults (reads never fault under CoW).
		run_config("reads-only",         master, options, 256, 0,   nullptr,    false, ITERS);
		// B: writes only -> CoW write-fault baseline.
		run_config("writes-only",        master, options, 0,   256, nullptr,    false, ITERS);
		// C: mixed -> faults should match B (reads add nothing).
		run_config("mixed",              master, options, 256, 256, nullptr,    false, ITERS);
		// D: mixed + write-prefetch -> faults drop to ~0; cost moves to batch pre-CoW.
		run_config("mixed+writeprefetch", master, options, 256, 256, &write_set, false, ITERS);
		// E/F: same, but reusing one fork via fast reset_to (steady-state harness).
		run_config("mixed+reset",        master, options, 256, 256, nullptr,    true,  ITERS);
		run_config("mixed+reset+wpf",    master, options, 256, 256, &write_set, true,  ITERS);
		std::printf("-----------------------------------------------------------------------------\n");
		std::printf("Read faults are structurally 0 (reads-only row), so read-tracking (Option B)\n");
		std::printf("has nothing to prefetch in this model. Compare writes-only vs +writeprefetch\n");
		std::printf("to see the write-set (Option A) prefetch trade-off.\n");
		return 0;
	} catch (const tinykvm::MachineException& e) {
		std::fprintf(stderr, "Benchmark failed: %s (data=0x%lX)\n", e.what(), e.data());
		return 1;
	} catch (const std::exception& e) {
		std::fprintf(stderr, "Benchmark failed: %s\n", e.what());
		return 1;
	}
}
