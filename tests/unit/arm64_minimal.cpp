#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <string_view>
#include <vector>
#include <sys/mman.h>
#include <unistd.h>
#include <tinykvm/arm64/memory_layout.hpp>
#include <tinykvm/machine.hpp>
#include <tinykvm/paging.hpp>

static constexpr uint64_t MAX_MEMORY = 2ul << 20;
static constexpr uint64_t CODE_ADDR = 0x100000;
static constexpr uint64_t DATA_ADDR = 0x101000;
static constexpr uint64_t STACK_ADDR = 0x180000;

static const std::array<uint32_t, 4> minimal_guest {
	0x91001C24, // add x4, x1, #7
	0xF9000044, // str x4, [x2]
	0xAA0403E0, // mov x0, x4
	0xF9000060, // str x0, [x3]
};

static const std::array<uint32_t, 7> syscall_guest {
	0xD4000001, // svc #0
	0xAA0003E1, // mov x1, x0
	0xD2800F88, // mov x8, #124
	0xD4000001, // svc #0
	0xF9000060, // str x0, [x3]
	0xF9000041, // str x1, [x2]
	0xF9000080, // str x0, [x4]
};

static const std::array<uint32_t, 2> ret_guest {
	0x91000400, // add x0, x0, #1
	0xD65F03C0, // ret
};

static const std::array<uint32_t, 4> cow_guest {
	0xF9000041, // str x1, [x2]
	0xF9400040, // ldr x0, [x2]
	0xF9000060, // str x0, [x3]
	0xF9000080, // str x0, [x4]
};

static const std::array<uint32_t, 3> cntvct_guest {
	0xD53BE040, // mrs x0, cntvct_el0
	0xF9000040, // str x0, [x2]   (DATA_ADDR)
	0xF9000060, // str x0, [x3]   (STOP MMIO -> exit)
};

static bool contains_page(const std::vector<std::pair<uint64_t, uint64_t>>& pages,
	uint64_t addr)
{
	for (const auto& [base, size] : pages) {
		if (base <= addr && addr < base + size) {
			return true;
		}
	}
	return false;
}

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

TEST_CASE("ARM64 raw guest exits through TinyKVM MMIO ABI", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	machine.copy_to_guest(CODE_ADDR, minimal_guest.data(),
		minimal_guest.size() * sizeof(minimal_guest[0]));

	auto regs = machine.registers();
	regs.pc = CODE_ADDR;
	regs.sp = STACK_ADDR;
	regs.pstate = 0x3c0;
	regs.regs[1] = 35;
	regs.regs[2] = DATA_ADDR;
	regs.regs[3] = tinykvm::ARM64_STOP_MMIO_ADDR;
	machine.set_registers(regs);

	machine.run(1.0f);

	const auto& out_regs = machine.registers();
	uint64_t stored = 0;
	machine.copy_from_guest(&stored, DATA_ADDR, sizeof(stored));

	REQUIRE(machine.stopped());
	REQUIRE(stored == 42);
	REQUIRE(out_regs.regs[0] == 42);
	REQUIRE(out_regs.sp == STACK_ADDR);
	// The stop MMIO store is completed eagerly, so PC is past the last insn.
	REQUIRE(out_regs.pc == CODE_ADDR + minimal_guest.size() * sizeof(minimal_guest[0]));
}

TEST_CASE("ARM64 SVC guest exits through TinyKVM syscall MMIO ABI", "[arm64]")
{
	require_arm64_kvm();

	tinykvm::Machine::install_syscall_handler(123, [] (tinykvm::vCPU& cpu) {
		auto regs = cpu.registers();
		regs.sysret() = 0x111;
		cpu.set_registers(regs);
	});
	tinykvm::Machine::install_syscall_handler(124, [] (tinykvm::vCPU& cpu) {
		auto regs = cpu.registers();
		regs.sysret() = regs.sysarg(0) + 0x10;
		cpu.set_registers(regs);
	});

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	machine.copy_to_guest(CODE_ADDR, syscall_guest.data(),
		syscall_guest.size() * sizeof(syscall_guest[0]));

	auto regs = machine.registers();
	regs.pc = CODE_ADDR;
	regs.sp = STACK_ADDR;
	regs.pstate = 0x3c0;
	regs.regs[2] = DATA_ADDR;
	regs.regs[3] = DATA_ADDR + sizeof(uint64_t);
	regs.regs[4] = tinykvm::ARM64_STOP_MMIO_ADDR;
	regs.regs[8] = 123;
	machine.set_registers(regs);

	machine.run(1.0f);

	uint64_t first = 0;
	uint64_t second = 0;
	machine.copy_from_guest(&first, DATA_ADDR, sizeof(first));
	machine.copy_from_guest(&second, DATA_ADDR + sizeof(uint64_t), sizeof(second));

	REQUIRE(machine.stopped());
	REQUIRE(first == 0x111);
	REQUIRE(second == 0x121);
	REQUIRE(machine.registers().pc == CODE_ADDR + syscall_guest.size() * sizeof(syscall_guest[0]));
}

TEST_CASE("ARM64 vmcall returns through LR stop stub", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	machine.copy_to_guest(CODE_ADDR, ret_guest.data(),
		ret_guest.size() * sizeof(ret_guest[0]));

	machine.vmcall(CODE_ADDR, 41);

	REQUIRE(machine.stopped());
	REQUIRE(machine.registers().regs[0] == 42);
}

TEST_CASE("ARM64 copy_to_guest preserves source when zeroes hint is set", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	__u64 sp = STACK_ADDR;
	const uint64_t addr = machine.stack_push_cstr(sp, "tiny");
	char buffer[5] {};
	machine.copy_from_guest(buffer, addr, sizeof(buffer));
	REQUIRE(std::string_view(buffer, sizeof(buffer)) == std::string_view("tiny\0", 5));
}

TEST_CASE("ARM64 fork uses copy-on-write for guest stores", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	const tinykvm::MachineOptions options {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = 2u << 20,
		.split_hugepages = true,
	};

	tinykvm::Machine master {empty_binary, options};
	master.copy_to_guest(CODE_ADDR, cow_guest.data(),
		cow_guest.size() * sizeof(cow_guest[0]));
	const uint64_t original = 0x1234;
	master.copy_to_guest(DATA_ADDR, &original, sizeof(original));
	master.prepare_copy_on_write(options.max_cow_mem);

	tinykvm::Machine fork {master, options};
	auto regs = fork.registers();
	regs.pc = CODE_ADDR;
	regs.sp = STACK_ADDR;
	regs.pstate = 0x3c0;
	regs.regs[1] = 0xABCDEF;
	regs.regs[2] = DATA_ADDR;
	regs.regs[3] = DATA_ADDR + sizeof(uint64_t);
	regs.regs[4] = tinykvm::ARM64_STOP_MMIO_ADDR;
	fork.set_registers(regs);

	fork.run(1.0f);

	uint64_t fork_value = 0;
	uint64_t master_value = 0;
	uint64_t observed = 0;
	fork.copy_from_guest(&fork_value, DATA_ADDR, sizeof(fork_value));
	fork.copy_from_guest(&observed, DATA_ADDR + sizeof(uint64_t), sizeof(observed));
	master.copy_from_guest(&master_value, DATA_ADDR, sizeof(master_value));

	REQUIRE(fork_value == 0xABCDEF);
	REQUIRE(observed == 0xABCDEF);
	REQUIRE(master_value == original);
	REQUIRE(contains_page(fork.get_accessed_pages(), DATA_ADDR));

	fork.reset_to(master, options);
	fork.copy_from_guest(&fork_value, DATA_ADDR, sizeof(fork_value));
	REQUIRE(fork_value == original);
}

TEST_CASE("ARM64 fork re-runs correctly after reset_to", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	const tinykvm::MachineOptions options {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = 2u << 20,
		.split_hugepages = true,
	};

	tinykvm::Machine master {empty_binary, options};
	master.copy_to_guest(CODE_ADDR, cow_guest.data(),
		cow_guest.size() * sizeof(cow_guest[0]));
	const uint64_t original = 0x1234;
	master.copy_to_guest(DATA_ADDR, &original, sizeof(original));
	master.prepare_copy_on_write(options.max_cow_mem);

	tinykvm::Machine fork {master, options};
	for (int i = 0; i < 4; i++) {
		const uint64_t value = 0xABCDEF00 + i;
		auto regs = fork.registers();
		regs.pc = CODE_ADDR;
		regs.sp = STACK_ADDR;
		regs.pstate = 0x3c0;
		regs.regs[1] = value;
		regs.regs[2] = DATA_ADDR;
		regs.regs[3] = DATA_ADDR + sizeof(uint64_t);
		regs.regs[4] = tinykvm::ARM64_STOP_MMIO_ADDR;
		fork.set_registers(regs);

		fork.run(1.0f);

		uint64_t fork_value = 0;
		uint64_t observed = 0;
		uint64_t master_value = 0;
		fork.copy_from_guest(&fork_value, DATA_ADDR, sizeof(fork_value));
		fork.copy_from_guest(&observed, DATA_ADDR + sizeof(uint64_t), sizeof(observed));
		master.copy_from_guest(&master_value, DATA_ADDR, sizeof(master_value));
		REQUIRE(fork_value == value);
		REQUIRE(observed == value);
		REQUIRE(master_value == original);

		fork.reset_to(master, options);
		fork.copy_from_guest(&fork_value, DATA_ADDR, sizeof(fork_value));
		REQUIRE(fork_value == original);
	}
}

TEST_CASE("ARM64 prefetch_pages pre-CoWs a harvested write set", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	const tinykvm::MachineOptions options {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = 2u << 20,
		.split_hugepages = true,
	};

	tinykvm::Machine master {empty_binary, options};
	master.copy_to_guest(CODE_ADDR, cow_guest.data(),
		cow_guest.size() * sizeof(cow_guest[0]));
	const uint64_t original = 0x1234;
	master.copy_to_guest(DATA_ADDR, &original, sizeof(original));
	master.prepare_copy_on_write(options.max_cow_mem);

	auto run_guest = [&] (tinykvm::Machine& m, uint64_t value) {
		auto regs = m.registers();
		regs.pc = CODE_ADDR;
		regs.sp = STACK_ADDR;
		regs.pstate = 0x3c0;
		regs.regs[1] = value;
		regs.regs[2] = DATA_ADDR;
		regs.regs[3] = DATA_ADDR + sizeof(uint64_t);
		regs.regs[4] = tinykvm::ARM64_STOP_MMIO_ADDR;
		m.set_registers(regs);
		m.run(1.0f);
		uint64_t stored = 0;
		m.copy_from_guest(&stored, DATA_ADDR, sizeof(stored));
		REQUIRE(stored == value);
	};

	// Warmup fork: run once and harvest the write working set.
	std::vector<std::pair<uint64_t, uint64_t>> write_set;
	{
		tinykvm::Machine warmup {master, options};
		run_guest(warmup, 0xAAAA);
		write_set = warmup.get_accessed_pages();
	}
	REQUIRE(contains_page(write_set, DATA_ADDR));

	// Steady-state fork: replaying the set pre-CoWs the pages (they show as
	// accessed before any guest run) and the run takes zero write faults.
	tinykvm::Machine fork {master, options};
	REQUIRE(fork.prefetch_pages(write_set) >= 1);
	REQUIRE(contains_page(fork.get_accessed_pages(), DATA_ADDR));

	fork.set_profiling(true);
	run_guest(fork, 0xBBBB);
	const auto& faults =
		fork.profiling()->times.at(tinykvm::MachineProfiling::PageFault);
	REQUIRE(faults.empty());

	// Same through the fast-reset path used by the per-agent loop.
	fork.reset_to(master, options);
	uint64_t after_reset = 0;
	fork.copy_from_guest(&after_reset, DATA_ADDR, sizeof(after_reset));
	REQUIRE(after_reset == original);
	fork.prefetch_pages(write_set);

	fork.set_profiling(false); // fresh profiler for the post-reset run
	fork.set_profiling(true);
	run_guest(fork, 0xCCCC);
	const auto& reset_faults =
		fork.profiling()->times.at(tinykvm::MachineProfiling::PageFault);
	REQUIRE(reset_faults.empty());
}

TEST_CASE("ARM64 reports dirty pages written through host API", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	const uint64_t value = 0xA55A;
	machine.copy_to_guest(DATA_ADDR, &value, sizeof(value));

	REQUIRE(contains_page(machine.get_accessed_pages(), DATA_ADDR));
}

TEST_CASE("ARM64 merges uniform 4 KiB leaves into an L2 block", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, {
		.max_mem = MAX_MEMORY,
		.max_cow_mem = tinykvm::vMemory::PageSize(),
	}};
	auto& memory = machine.main_memory();
	const uint64_t addr_mask = tinykvm::paging_address_mask();
	// The first 2MB region is an L3 table (kernel pages + null guard), so use
	// the next region, which is a plain identity-mapped 2MB block.
	const uint64_t block_addr = 1ULL << 21;

	tinykvm::page_at(memory, block_addr,
	[&memory, addr_mask] (uint64_t, uint64_t& entry, size_t size) {
		REQUIRE(size == (1ULL << 21));
		auto page = memory.new_page();
		const uint64_t base = entry & addr_mask;
		const uint64_t flags = entry & ~addr_mask;
		for (size_t i = 0; i < 512; i++) {
			page.pmem[i] = (base + i * tinykvm::vMemory::PageSize()) | flags | (1ULL << 1);
		}
		entry = page.addr | 0x3ULL;
	});

	REQUIRE(memory.merge_leaf_pages_into_hugepages() == 512);

	tinykvm::page_at(memory, block_addr,
	[] (uint64_t, uint64_t&, size_t size) {
		REQUIRE(size == (1ULL << 21));
	});
}

TEST_CASE("ARM64 snapshot restores CPU and memory state", "[arm64]")
{
	require_arm64_kvm();

	char path[] = "/tmp/tinykvm-arm64-snapshot-XXXXXX";
	int fd = mkstemp(path);
	REQUIRE(fd >= 0);
	close(fd);

	const std::vector<uint8_t> empty_binary;
	tinykvm::MachineOptions create_options {
		.max_mem = MAX_MEMORY,
		.mmap_backed_files = false,
		.snapshot_file = path,
		.snapshot_mode = tinykvm::MachineOptions::SnapshotMode::Create,
	};
	const uint64_t marker = 0xFEEDBEEF;
	{
		tinykvm::Machine machine {empty_binary, create_options};
		machine.copy_to_guest(DATA_ADDR, &marker, sizeof(marker));
		auto regs = machine.registers();
		regs.pc = CODE_ADDR;
		regs.sp = STACK_ADDR;
		regs.pstate = 0x3c0;
		regs.regs[0] = 0x12345678;
		machine.set_registers(regs);
		machine.save_snapshot_state_now();
	}

	tinykvm::MachineOptions open_options = create_options;
	open_options.snapshot_mode = tinykvm::MachineOptions::SnapshotMode::Open;
	tinykvm::Machine restored {empty_binary, open_options};

	uint64_t loaded_marker = 0;
	restored.copy_from_guest(&loaded_marker, DATA_ADDR, sizeof(loaded_marker));
	REQUIRE(restored.has_snapshot_state());
	REQUIRE(loaded_marker == marker);
	REQUIRE(restored.registers().pc == CODE_ADDR);
	REQUIRE(restored.registers().sp == STACK_ADDR);
	REQUIRE(restored.registers().regs[0] == 0x12345678);

	unlink(path);
}

// Bit layout of an ARM64 stage-1 descriptor (mirrors arm64/paging.cpp).
static constexpr uint64_t TEST_DESC_AP_RO    = 1ULL << 7;
static constexpr uint64_t TEST_DESC_CLONEABLE = 1ULL << 56;

TEST_CASE("ARM64 host write promotes a read-only non-cloneable block", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, {
		.max_mem = 8ull << 20,
		.max_cow_mem = 4u << 20,
		.split_hugepages = true,
	}};
	auto& memory = machine.main_memory();

	// Second 2MB region: a plain identity-mapped L2 block (the first 2MB is an
	// L3 table holding the kernel pages + null guard).
	const uint64_t block_addr = 1ULL << 21;            // 0x200000
	const uint64_t write_addr = block_addr + 0x50000;  // unaligned into the block

	// Reproduce the page shape that crashed master boot: a valid, read-only,
	// NON-cloneable 2MB block. That is exactly what mmap_backed_area installs
	// for a large PROT_READ (.so) mapping, and which makecow then leaves alone
	// because it only marks *writable* pages copy-on-write.
	tinykvm::page_at(memory, block_addr,
	[] (uint64_t, uint64_t& entry, size_t size) {
		REQUIRE(size == (1ULL << 21));
		entry |= TEST_DESC_AP_RO;
		entry &= ~TEST_DESC_CLONEABLE;
	});

	// The mmap syscall handler fills a freshly-mapped region that overlaps this
	// span with a host-side write (memzero / preadv -> writable_buffers_from_range
	// -> writable_page_at). That must promote the page, not throw
	// "writable_page_at: l2 entry not writable".
	const uint64_t value = 0xC0FFEE1234ull;
	REQUIRE_NOTHROW(machine.copy_to_guest(write_addr, &value, sizeof(value)));

	uint64_t readback = 0;
	machine.copy_from_guest(&readback, write_addr, sizeof(readback));
	REQUIRE(readback == value);
}

TEST_CASE("ARM64 fork write to a read-only non-cloneable page stays private", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	const tinykvm::MachineOptions options {
		.max_mem = 8ull << 20,
		.max_cow_mem = 4u << 20,
		.split_hugepages = true,
	};
	const uint64_t block_addr = 1ULL << 21;
	const uint64_t write_addr = block_addr + 0x50000;
	const uint64_t original = 0x1111111111111111ull;

	tinykvm::Machine master {empty_binary, options};
	master.copy_to_guest(write_addr, &original, sizeof(original));
	// Make the block read-only + non-cloneable (the file-backed .so shape).
	// makecow leaves it untouched because it is not writable, so the fork
	// inherits a page that points at the *shared* master memory.
	tinykvm::page_at(master.main_memory(), block_addr,
	[] (uint64_t, uint64_t& entry, size_t) {
		entry |= TEST_DESC_AP_RO;
		entry &= ~TEST_DESC_CLONEABLE;
	});
	master.prepare_copy_on_write(options.max_cow_mem);

	tinykvm::Machine fork {master, options};
	const uint64_t updated = 0x2222222222222222ull;
	REQUIRE_NOTHROW(fork.copy_to_guest(write_addr, &updated, sizeof(updated)));

	uint64_t fork_value = 0;
	uint64_t master_value = 0;
	fork.copy_from_guest(&fork_value, write_addr, sizeof(fork_value));
	master.copy_from_guest(&master_value, write_addr, sizeof(master_value));

	// The fork sees its own write; the shared master page must be untouched.
	// (Invariant: no cross-session bleed through a read-only shared page.)
	REQUIRE(fork_value == updated);
	REQUIRE(master_value == original);
}

TEST_CASE("ARM64 read-only file-backed protections stay EL0-executable", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, {
		.max_mem = 8ull << 20,
		.max_cow_mem = 4u << 20,
		.split_hugepages = true,
	}};
	auto& memory = machine.main_memory();

	constexpr uint64_t DESC_UXN = 1ULL << 54;
	const uint64_t addr = (1ULL << 21) + 0x1000;

	// mmap_backed_area protects a large .so's PROT_READ reservation via
	// set_protections(PROT_READ). Because mprotect() is a no-op on this port and
	// guest RAM is otherwise uniformly EL0-executable, that must NOT mark the
	// page execute-never (UXN): a .so text segment loaded through this path
	// would then fault (EC 0x20, instruction abort) on first fetch, with no way
	// for the loader's later PROT_EXEC mprotect() to recover.
	tinykvm::WritablePage page =
		writable_page_at(memory, addr, tinykvm::paging_default_usermode_flags(false));
	page.set_protections(PROT_READ);

	bool uxn_set = false;
	tinykvm::page_at(memory, addr,
	[&] (uint64_t, uint64_t& entry, size_t) {
		uxn_set = (entry & DESC_UXN) != 0;
	});
	REQUIRE(!uxn_set);
}

TEST_CASE("ARM64 EL0 reads cntvct_el0 without trapping", "[arm64]")
{
	require_arm64_kvm();

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	machine.copy_to_guest(CODE_ADDR, cntvct_guest.data(),
		cntvct_guest.size() * sizeof(cntvct_guest[0]));

	auto regs = machine.registers();
	regs.pc = CODE_ADDR;
	regs.sp = STACK_ADDR;
	regs.pstate = 0x3c0;       // EL0t
	regs.regs[0] = 0xDEADBEEF; // sentinel the MRS must overwrite
	regs.regs[2] = DATA_ADDR;
	regs.regs[3] = tinykvm::ARM64_STOP_MMIO_ADDR;
	machine.set_registers(regs);

	// `mrs x0, cntvct_el0` from EL0 traps (ESR EC=0x18) and aborts the guest
	// unless CNTKCTL_EL1.EL0VCTEN is set. Ordinary timing code (e.g. numpy's
	// bundled OpenBLAS during CPU detection) emits exactly this instruction.
	REQUIRE_NOTHROW(machine.run(1.0f));

	uint64_t counter = 0;
	machine.copy_from_guest(&counter, DATA_ADDR, sizeof(counter));
	REQUIRE(machine.stopped());
	REQUIRE(counter != 0xDEADBEEF); // the counter read actually executed
}
