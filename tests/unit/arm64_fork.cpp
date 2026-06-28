#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <tinykvm/machine.hpp>

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
