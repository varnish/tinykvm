/**
 * Snapshot-load ordering benchmark.
 *
 * Measures the cost of cold-loading a VM snapshot under three different
 * physical page-ordering strategies:
 *
 *   1. NO ORDER     - snapshot saved with no prefetch hints. Pages are
 *                     demand-faulted from the file in whatever order the
 *                     workload touches them (scattered random file IO).
 *   2. ACCESS ORDER - prefetch the accessed working set discovered via the
 *                     page-table accessed bits (get_accessed_pages()). The
 *                     pages stay at their original physical offsets, so the
 *                     prefetched ranges are scattered across the file.
 *   3. FAULT ORDER  - reorder_snapshot_memory() physically relocates the
 *                     faulted pages so they are contiguous and in first-touch
 *                     order. Prefetch then reads one sequential file region.
 *
 * Each strategy produces its own snapshot file. The load phase drops the OS
 * page cache before every trial (needs root) so each measurement reflects a
 * genuine cold start from disk, then loads the snapshot and brings the booted
 * working set resident, timing the whole thing in wall-clock.
 */
#include <tinykvm/machine.hpp>
#include <algorithm>
#include <cstring>
#include <cstdio>
#include <ctime>
#include <fcntl.h>
#include <unistd.h>
#include "load_file.hpp"

#define GUEST_MEMORY   1024UL * 1024 * 1024  /* 1024MB main memory */
#define GUEST_WORK_MEM 256UL * 1024 * 1024   /* 256MB working memory  */
static const std::string ld_linux_so = "/lib64/ld-linux-x86-64.so.2";
static const char* DEFAULT_GUEST = "../guest/glibc/glibc.static";
static constexpr int  TRIALS = 8;

/* Wall-clock, not CPU time: cold page faults block on IO and that time must
   be counted. timing.hpp uses CLOCK_THREAD_CPUTIME_ID which would hide it. */
static inline timespec time_now()
{
	timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t;
}
static inline double seconds_between(timespec a, timespec b)
{
	return (b.tv_sec - a.tv_sec) + (b.tv_nsec - a.tv_nsec) / 1e9;
}

struct Stats {
	double avg = 0, median = 0, p90 = 0, min = 0, max = 0;
};
static Stats summarize(std::vector<double> v)
{
	Stats s;
	if (v.empty()) return s;
	std::sort(v.begin(), v.end());
	double total = 0;
	for (double x : v) total += x;
	s.avg = total / v.size();
	s.median = v[v.size() / 2];
	s.p90 = v[static_cast<size_t>(v.size() * 0.9)];
	s.min = v.front();
	s.max = v.back();
	return s;
}

/* Drop the OS page cache so the next snapshot load is a genuine cold start.
   Requires root (or CAP_SYS_ADMIN). Returns false if it could not be done. */
static bool drop_caches()
{
	sync();
	int fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (fd < 0)
		return false;
	const char* three = "3\n";
	ssize_t w = write(fd, three, 2);
	close(fd);
	return w == 2;
}

enum Strategy { NO_ORDER = 0, ACCESS_ORDER = 1, FAULT_ORDER = 2 };
static const char* strategy_name(Strategy s)
{
	switch (s) {
		case NO_ORDER:     return "no-order     ";
		case ACCESS_ORDER: return "access-order ";
		case FAULT_ORDER:  return "fault-order  ";
	}
	return "?";
}

static std::vector<uint8_t> g_binary;     // ld-linux.so or the static guest
static std::vector<std::string> g_args;   // guest argv
static bool g_is_dynamic = false;
static std::string g_entry = "test";      // workload entrypoint to replay
static uint64_t g_entry_addr = 0x0;        // resolved VA (snapshots skip symbol load)

/* Working set captured (by virtual address) from the freshly-booted master.
   The same set is touched on every loaded snapshot so all three strategies
   are measured bringing in the identical logical pages, differing only by
   physical layout and prefetch hint. */
static std::vector<std::pair<uint64_t, uint64_t>> g_working_set;

static tinykvm::MachineOptions base_options(const std::string& snapshot_file,
	tinykvm::MachineOptions::SnapshotMode mode)
{
	tinykvm::MachineOptions options {
		.max_mem = GUEST_MEMORY,
		.max_cow_mem = GUEST_WORK_MEM,
		.dylink_address_hint = 0x400000,
		.verbose_loader = false,
		// Force 4KB pages so the workload's per-page access order actually
		// determines the physical/file layout (2MB identity pages would make
		// a per-4KB shuffle meaningless — 512 sub-pages share one mapping).
		.split_all_hugepages_during_loading = true,
		.executable_heap = g_is_dynamic,
		.mmap_backed_files = false, // incompatible with snapshot files
	};
	options.snapshot_file = snapshot_file;
	options.snapshot_mode = mode;
	return options;
}

/* Boot a master VM, apply the ordering strategy, and persist a snapshot file.
   Captures g_working_set on the first (NO_ORDER) build. */
static void build_snapshot(Strategy strat, const std::string& path)
{
	auto options = base_options(path, tinykvm::MachineOptions::SnapshotMode::Create);
	tinykvm::Machine master {g_binary, options};
	master.fds().set_open_readable_callback([] (std::string&) -> bool { return true; });
	master.setup_linux(g_args, {"LC_TYPE=C", "LC_ALL=C", "USER=root"});

	/* Boot to main() */
	master.run(8.0f);

	const uint64_t entry = master.address_of(g_entry);
	g_entry_addr = entry; // stable VA, reused on restored snapshots (no symbols)

	std::vector<std::pair<uint64_t, uint64_t>> populate;
	size_t fault_pages = 0;

	if (strat == ACCESS_ORDER) {
		populate = master.get_accessed_pages();
	}
	else if (strat == FAULT_ORDER) {
		/* Record the order in which the workload first touches each physical
		   page, by clearing the present bit on every user page and letting the
		   replayed request fault them back in one by one. */
		std::vector<uint64_t> fault_order;
		master.make_unpresented_with_callback(
			[&fault_order] (uint64_t paddr, uint64_t /*vaddr*/) {
				fault_order.push_back(paddr);
			});
		if (entry != 0x0) {
			try {
				master.vmcall(entry);
			} catch (const std::exception& e) {
				fprintf(stderr, "  (fault-order replay of '%s' threw: %s)\n",
					g_entry.c_str(), e.what());
			}
		}
		master.restore_unpresented_pages();
		fault_pages = fault_order.size();
		populate = master.reorder_snapshot_memory(fault_order);
	}

	/* Capture the working set once, from a clean (non-reordered) boot. */
	if (strat == NO_ORDER) {
		g_working_set = master.get_accessed_pages();
	}

	master.save_snapshot_state_now(populate);

	printf("  built %s: %zu accessed pages, %zu fault-order pages, %zu prefetch ranges\n",
		strategy_name(strat),
		(strat == NO_ORDER) ? g_working_set.size() : master.get_accessed_pages().size(),
		fault_pages, populate.size());
	// master destroyed here -> MAP_SHARED memory flushed to the snapshot file
}

/* Replay the request entrypoint, which streams the working set in its fixed
   scattered page order. This is the measured consumer: it brings pages
   resident in the SAME order the fault-order snapshot was laid out for, so a
   sequential physical layout turns into sequential file IO (and a scattered
   layout into random file IO). Returns the pages faulted in by the request. */
static size_t replay_request(tinykvm::Machine& vm)
{
	const uint64_t entry = g_entry_addr;
	if (entry == 0x0)
		return 0;
	try {
		vm.vmcall(entry);
	} catch (const std::exception& e) {
		fprintf(stderr, "  (replay of '%s' threw: %s)\n", g_entry.c_str(), e.what());
	}
	// Pages actually brought resident by the request, via accessed bits.
	size_t pages = 0;
	for (const auto& [vaddr, size] : vm.get_accessed_pages())
		{ (void)vaddr; pages += size / 0x1000; }
	return pages;
}

/* Cold-load a snapshot and run the request against it, timed end to end. */
static double timed_cold_load(const std::string& path, bool can_drop, size_t* out_touched)
{
	if (can_drop)
		drop_caches();

	auto options = base_options(path, tinykvm::MachineOptions::SnapshotMode::Open);

	asm("" ::: "memory");
	auto t0 = time_now();
	asm("" ::: "memory");

	tinykvm::Machine restored {g_binary, options};
	if (!restored.has_snapshot_state())
		fprintf(stderr, "  WARNING: VM did not load from snapshot state!\n");
	size_t touched = replay_request(restored);

	asm("" ::: "memory");
	auto t1 = time_now();
	asm("" ::: "memory");

	if (out_touched) *out_touched = touched;
	return seconds_between(t0, t1);
}

int main(int argc, char** argv)
{
	setvbuf(stdout, nullptr, _IONBF, 0);
	const std::string guest_path = (argc > 1) ? argv[1] : DEFAULT_GUEST;
	if (const char* e = getenv("ENTRY")) g_entry = e;

	auto original = load_file(guest_path);
	const tinykvm::DynamicElf dyn = tinykvm::is_dynamic_elf(
		std::string_view{(const char*)original.data(), original.size()});
	g_is_dynamic = dyn.is_dynamic;
	if (g_is_dynamic) {
		g_binary = load_file(ld_linux_so);
		g_args.push_back(ld_linux_so);
	} else {
		g_binary = std::move(original);
	}
	g_args.push_back(guest_path);

	printf(">>> Guest: %s (%s), replay entry '%s', %d trials\n",
		guest_path.c_str(), g_is_dynamic ? "dynamic" : "static",
		g_entry.c_str(), TRIALS);

	tinykvm::Machine::init();
	tinykvm::Machine::setup_linux_system_calls();
	tinykvm::Machine::install_unhandled_syscall_handler(
		[] (tinykvm::vCPU& cpu, unsigned scall) {
			if (scall == 0x10000) { cpu.stop(); return; }
			auto regs = cpu.registers();
			regs.rax = -ENOSYS;
			cpu.set_registers(regs);
		});

	/* Verify we can actually measure cold loads. */
	const bool can_drop = drop_caches();
	if (!can_drop) {
		fprintf(stderr,
			"WARNING: cannot drop the page cache (need root). Results will be\n"
			"         WARM and will not reflect cold-start IO differences.\n"
			"         Re-run with sudo for meaningful numbers.\n");
	}

	/* Build all three snapshot files. */
	const char* paths[3] = {
		"/tmp/tinykvm-snap-noorder",
		"/tmp/tinykvm-snap-access",
		"/tmp/tinykvm-snap-fault",
	};
	printf("\n=== Building snapshots ===\n");
	for (int s = 0; s < 3; s++) {
		unlink(paths[s]);
		build_snapshot(Strategy(s), paths[s]);
	}
	printf("Working set to touch on load: %zu ranges\n", g_working_set.size());

	/* Load phase. */
	printf("\n=== Cold load (%d trials each) ===\n", TRIALS);
	for (int s = 0; s < 3; s++) {
		std::vector<double> times;
		size_t touched = 0;
		for (int t = 0; t < TRIALS; t++)
			times.push_back(timed_cold_load(paths[s], can_drop, &touched));
		Stats st = summarize(times);
		printf("%s med %7.2f ms  avg %7.2f ms  p90 %7.2f ms  min %7.2f ms  max %7.2f ms  (%zu pages)\n",
			strategy_name(Strategy(s)),
			st.median * 1e3, st.avg * 1e3, st.p90 * 1e3,
			st.min * 1e3, st.max * 1e3, touched);
	}

	for (int s = 0; s < 3; s++)
		unlink(paths[s]);
	return 0;
}
