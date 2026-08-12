#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <tinykvm/machine.hpp>
#include <tinykvm/linux/threads.hpp>
#include <sys/wait.h>
#include <unistd.h>

extern std::pair<std::string, std::vector<uint8_t>>
	build_and_load(const std::string& code, const std::string& args);

static const uint64_t MAX_MEMORY = 64ul << 20; /* 64MB */
static const uint64_t MAX_COWMEM = 16ul << 20; /* 16MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};

static void require_arm64_kvm()
{
	static bool attempted = false;
	static bool available = false;
	static std::string error;
	if (!attempted) {
		attempted = true;
		try {
			tinykvm::Machine::init();
			available = true;
		} catch (const tinykvm::MachineException& e) {
			error = std::string(e.what()) + " (" + std::to_string(e.data()) + ")";
		}
	}
	if (!available) {
		SKIP("ARM64 KVM unavailable: " << error);
	}
}

// Regression test for cow_page() zeroing initialized data on the first write in
// a fork. cow_page() treated a clear DESC_DIRTY bit as "this page is zero" and
// zeroed the freshly-allocated copy-on-write page instead of duplicating the
// master page. But the master page is the CoW source of truth and a clean
// (!dirty) page can still hold non-zero content: the ELF loader populates .data
// with a raw memcpy into the backing store (vMemory::at) that never sets
// DESC_DIRTY, and split_l2_block() then propagates that clear bit to every 4KB
// page it splits out of a 2MB block. The old code zeroed such pages on first
// write after a fork, destroying the data (observed in the field as glibc's
// stdin FILE pointers reading back NULL -> EL0 data abort on the first buffered
// read in a fork).
//
// This reproduces that state deterministically rather than relying on a fragile
// .data/.bss layout: a clean (zero-initialized, so cloneable with DESC_DIRTY
// clear after prepare_copy_on_write) guest buffer is populated from the host via
// unsafe_memory_at() -- the same dirty-bit-bypassing path the loader uses -- and
// then a fork writes one offset of each page and reads a sentinel planted at
// another offset of the *same* page. With the bug the CoW zeroes the page and
// the sentinel reads back 0.
TEST_CASE("ARM64 CoW preserves clean non-zero pages on first write in a fork", "[arm64][fork]")
{
	require_arm64_kvm();

	// 4 MiB of zero-initialized .bss: after prepare_copy_on_write its pages are
	// cloneable with DESC_DIRTY clear, and (being .bss) none are dirtied by the
	// loader's copy_to_guest -- the exact precondition the bug needs.
	static constexpr long BUF_PAGES = 1024;
	static constexpr uint64_t MAGIC = 0x0123456789ABCDEFULL;

	const auto [program, binary] = build_and_load(R"M(
#include <stdint.h>
#define BUF_PAGES 1024
#define MAGIC 0x0123456789ABCDEFULL
char buf[BUF_PAGES * 4096];
int main() { return 0; }
/* For each page: write offset 0 (forces copy-on-write of the page), then read
   the sentinel the host planted at offset 8 of the same page. Returns the count
   of pages whose sentinel survived -- BUF_PAGES when correct, fewer with the
   bug (a zeroed CoW page reads back 0). */
extern long cow_check(void) {
	long survived = 0;
	for (long i = 0; i < BUF_PAGES; i++) {
		volatile unsigned char* p = (volatile unsigned char*)&buf[i * 4096];
		p[0] = 0xAB;                                    /* write -> CoW page i */
		if (*(volatile uint64_t*)(p + 8) == MAGIC) survived++;
	}
	return survived;
})M", "");

	tinykvm::Machine machine { binary, {
		.max_mem = MAX_MEMORY, .split_hugepages = true
	} };
	machine.setup_linux({"fork"}, env);
	machine.run(8.0f);

	machine.prepare_copy_on_write();
	REQUIRE(machine.is_forkable());

	// Plant a non-zero sentinel at offset 8 of every page, writing straight into
	// the master's backing store (no DESC_DIRTY set) -- exactly how the ELF
	// loader populates initialized data.
	const uint64_t buf_addr = machine.address_of("buf");
	REQUIRE(buf_addr != 0x0);
	for (long i = 0; i < BUF_PAGES; i++) {
		char* p = machine.unsafe_memory_at(buf_addr + i * 4096 + 8, sizeof(MAGIC));
		std::memcpy(p, &MAGIC, sizeof(MAGIC));
	}

	tinykvm::Machine fork { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
		.split_hugepages = true
	} };

	const auto func = fork.address_of("cow_check");
	REQUIRE(func != 0x0);

	fork.timed_vmcall(func, 8.0f);
	REQUIRE(fork.return_value() == BUF_PAGES);
}

// Regression test for the cross-process master path (fast-agent issue #18),
// fixed on ARM64 by tinykvm#114 -- see that PR and docs/architecture/
// process-per-vm.md for the fd/ownership contract this locks in.
//
// --process-per-vm boots one master and fork()s a zygote; every worker then
// constructs its own TinyKVM fork of the inherited master from a *different*
// process than the one that built it. KVM binds a VM to the creating
// process's mm: any vCPU ioctl issued against the master's fd from another
// process fails with -EIO. Before tinykvm#114, setup_cow_mode() read five
// EL1 sysregs (MAIR/TCR/SCTLR/CPACR/VBAR) straight off the master's vcpu fd,
// and the constructor's other.registers() could fall back to the same fd
// whenever its register cache was cold -- both fine in-process, both -EIO
// from a worker, so *no* fork could be built on ARM64 and every turn failed
// (fast-agent issue #66). The fix snapshots that state
// (prepared_sysregs()/warmed register cache) into the master at
// prepare_copy_on_write() time, while its fd is still ioctl-able, so a
// worker never has to touch it.
//
// Masters "stay eager by construction": nothing about consuming a master
// from a different process should depend on state that was lazily faulted
// in and therefore never crossed the process boundary. Mirroring the real
// topology precisely (run() + prepare_copy_on_write() happen once, in the
// single-threaded parent, before the OS-level fork() below) is what makes
// this a faithful regression guard rather than a synthetic one.
TEST_CASE("ARM64 cross-process master path: a worker builds and runs its own fork", "[arm64][fork]")
{
	require_arm64_kvm();

	const auto [program, binary] = build_and_load(R"M(
int main() {
}
static int value = 0;
extern int get_value() {
	value++;
	return value;
})M", "");

	// 16K-page hosts need CoW pages split down from the paging library's
	// default block size for writable_page_at() to find a writable leaf
	// entry (see the other fork/reset options in this file and in
	// arm64_minimal.cpp -- every one of them sets this).
	const tinykvm::MachineOptions options {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
		.split_hugepages = true,
	};

	tinykvm::Machine machine { binary, options };
	machine.setup_linux({"fork"}, env);
	// Everything the fork constructor needs from the master must be settled
	// here, in the single-threaded parent, before the OS-level fork() below.
	machine.run(4.0f);
	machine.prepare_copy_on_write(65536);

	const auto get_value = machine.address_of("get_value");
	REQUIRE(get_value != 0x0);

	struct WorkerResult {
		bool constructed = false;
		bool ran_ok = false;
		bool reset_ok = false;
		bool ran_again_ok = false;
		long value1 = -1;
		long value2 = -1;
		char error[256] = {0};
	};

	int pipefd[2];
	REQUIRE(pipe(pipefd) == 0);

	fflush(nullptr);
	const pid_t pid = fork();
	REQUIRE(pid >= 0);

	if (pid == 0) {
		// Worker process: never touches the parent's `machine` object again
		// except through the state that crossed fork() -- no ioctl on the
		// master's vcpu fd is possible here (KVM binds the VM to the
		// creating process's mm), so any regression back to a live read of
		// `other`'s fd fails loudly with -EIO instead of silently.
		close(pipefd[0]);
		WorkerResult result{};
		try {
			tinykvm::Machine fork_vm { machine, options };
			result.constructed = true;

			fork_vm.timed_vmcall(get_value, 4.0f);
			result.value1 = fork_vm.return_value();
			result.ran_ok = (result.value1 == 1);

			// The process-per-vm worker lifecycle recycles across tenants via
			// reset_to() (process-per-vm.md, "Worker lifetime policy") --
			// still cross-process, still must not touch the master's fd.
			fork_vm.reset_to(machine, options);
			result.reset_ok = true;

			fork_vm.timed_vmcall(get_value, 4.0f);
			result.value2 = fork_vm.return_value();
			result.ran_again_ok = (result.value2 == 1);
		} catch (const std::exception& e) {
			strncpy(result.error, e.what(), sizeof(result.error) - 1);
		}
		[[maybe_unused]] const ssize_t w = write(pipefd[1], &result, sizeof(result));
		close(pipefd[1]);
		_exit(0);
	}

	close(pipefd[1]);
	WorkerResult result{};
	const ssize_t r = read(pipefd[0], &result, sizeof(result));
	close(pipefd[0]);

	int status = 0;
	REQUIRE(waitpid(pid, &status, 0) == pid);
	REQUIRE(WIFEXITED(status));
	REQUIRE(WEXITSTATUS(status) == 0);

	REQUIRE(r == (ssize_t) sizeof(result));
	INFO("worker error: " << result.error);
	REQUIRE(result.constructed);
	REQUIRE(result.ran_ok);
	REQUIRE(result.value1 == 1);
	REQUIRE(result.reset_ok);
	REQUIRE(result.ran_again_ok);
	REQUIRE(result.value2 == 1);

	// The master itself is unharmed: it is still forkable in the parent, and
	// a fresh fork built here (in-process this time) behaves identically.
	auto fork_in_parent = tinykvm::Machine { machine, options };
	fork_in_parent.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork_in_parent.return_value() == 1);
}

// Regression test for the fork-path set_tls_base seat/tid coupling (fast-agent
// issue #20), ARM64 side. MultiThreading::reset_to (lib/tinykvm/arm64/
// stubs.cpp) is unconditional on this arch -- unlike x86_64 it does not
// compare the fork's default tid (1) against the master's current one -- but
// it is the *only* place a fork's tpidr_el0 is ever set: ARM64's
// setup_cow_mode() only carries the five CoW-relevant EL1 sysregs (MAIR/TCR/
// SCTLR/CPACR/VBAR, see tinykvm#114) and never touches TPIDR_EL0. So this is
// not a redundant safety net the way it can be on x86_64 (whose setup_cow_mode
// also blanket-copies sregs, including FS/GS base, from the same master): if
// a master ever touched threads() and its current thread id is not 1, the
// fork's TLS base depends entirely on this call reading the right Thread
// record. Read it back with Machine::tpidr_el0() -- the helper named in
// AGENTS.md, which always issues a fresh KVM_GET_ONE_REG ioctl, no userspace
// cache to fool.
TEST_CASE("ARM64 fork inherits tpidr_el0 from master's non-default current thread", "[arm64][fork][threads]")
{
	require_arm64_kvm();

	const auto [program, binary] = build_and_load(R"M(
int main() {
}
extern int get_value() {
	return 42;
})M", "");

	tinykvm::Machine machine { binary, { .max_mem = MAX_MEMORY } };
	machine.setup_linux({"fork"}, env);
	machine.run(4.0f);

	static constexpr uint64_t TLS_MARKER = 0x0000133700001337ULL;
	static constexpr int NON_DEFAULT_TID = 7;

	// Master's calling thread is not the default tid (1) when it is
	// snapshotted. MultiThreading::reset_to() on this arch reads the Thread
	// record's own cached fsbase field directly (not a live register), so
	// that field -- not just the live tpidr_el0 -- must carry the marker.
	auto& thread = machine.threads().create(NON_DEFAULT_TID);
	thread.fsbase = TLS_MARKER;
	machine.threads().set_to_and_suspend_others(NON_DEFAULT_TID);
	machine.set_tls_base(TLS_MARKER);
	REQUIRE(machine.threads().gettid() == NON_DEFAULT_TID);
	REQUIRE(machine.tpidr_el0() == TLS_MARKER);

	machine.prepare_copy_on_write(65536);

	auto fork = tinykvm::Machine { machine, {
		.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
	}};

	// The fork's own thread bookkeeping followed the master's current
	// thread, not the default tid=1 every fresh MultiThreading starts with.
	REQUIRE(fork.threads().gettid() == NON_DEFAULT_TID);

	// tpidr_el0() always issues a fresh KVM_GET_ONE_REG ioctl -- already the
	// strongest possible confirmation, and correct before the fork ever runs.
	REQUIRE(fork.tpidr_el0() == TLS_MARKER);

	const auto get_value = fork.address_of("get_value");
	REQUIRE(get_value != 0x0);
	fork.timed_vmcall(get_value, 4.0f);
	REQUIRE(fork.return_value() == 42);

	// Still correct straight off the hardware register after running.
	REQUIRE(fork.tpidr_el0() == TLS_MARKER);
}
