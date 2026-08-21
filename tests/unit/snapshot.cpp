#include <catch2/catch_test_macros.hpp>

#include <tinykvm/machine.hpp>
#include <cstring>
#include <string>
#include <unistd.h>
extern std::vector<uint8_t> build_and_load(const std::string& code);
static const uint64_t MAX_MEMORY = 32ul << 20; /* 32MB */
static const std::vector<std::string> env {
	"LC_TYPE=C", "LC_ALL=C", "USER=root"
};
static const char* SNAPSHOT_PATH = "/tmp/tinykvm-unittest-snapshot";

static const std::string GUEST_CODE = R"M(
extern long write(int, const void*, unsigned long);
static char message[32] = "Hello Snapshot World";
static long counter = 0;
int main() {
}
extern long bump() {
	write(1, message, 20);
	return ++counter;
})M";

/* Snapshots are file-backed, so both the master and the restored VM
   use the same set of options, differing only in the snapshot mode. */
static tinykvm::MachineOptions snapshot_options(
	tinykvm::MachineOptions::SnapshotMode mode)
{
	tinykvm::MachineOptions options {
		.max_mem = MAX_MEMORY,
		/* Force 4KB pages so that reordering actually moves individual
		   pages around, instead of whole identity-mapped 2MB pages. */
		.split_all_hugepages_during_loading = true,
		.mmap_backed_files = false, /* incompatible with snapshot files */
	};
	options.snapshot_file = SNAPSHOT_PATH;
	options.snapshot_mode = mode;
	return options;
}

TEST_CASE("Initialize KVM", "[Initialize]")
{
	tinykvm::Machine::init();
}

TEST_CASE("Save and restore a VM snapshot", "[Snapshot]")
{
	const auto binary = build_and_load(GUEST_CODE);
	unlink(SNAPSHOT_PATH);

	uint64_t funcaddr = 0x0;
	{
		tinykvm::Machine master { binary,
			snapshot_options(tinykvm::MachineOptions::Create) };
		master.set_printer([] (const char*, size_t) {}); /* quiet */
		master.setup_linux({"snapshot"}, env);
		master.run(4.0f);

		funcaddr = master.address_of("bump");
		REQUIRE(funcaddr != 0x0);

		/* The accessed working set becomes the prefetch hint on load. */
		master.save_snapshot_state_now(master.get_accessed_pages());
	} // flushed to the snapshot file here

	std::string output;
	tinykvm::Machine restored { binary,
		snapshot_options(tinykvm::MachineOptions::Open) };
	REQUIRE(restored.has_snapshot_state());
	REQUIRE(!restored.main_memory().memory_reordered);
	restored.set_printer([&] (const char* data, size_t size) {
		output.append(data, size);
	});

	restored.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(restored.return_value() == 1);
	REQUIRE(output == "Hello Snapshot World");

	unlink(SNAPSHOT_PATH);
}

TEST_CASE("Restore a snapshot with a limited prefetch budget", "[Snapshot]")
{
	const auto binary = build_and_load(GUEST_CODE);
	unlink(SNAPSHOT_PATH);

	uint64_t funcaddr = 0x0;
	{
		tinykvm::Machine master { binary,
			snapshot_options(tinykvm::MachineOptions::Create) };
		master.set_printer([] (const char*, size_t) {}); /* quiet */
		master.setup_linux({"snapshot"}, env);
		master.run(4.0f);
		funcaddr = master.address_of("bump");
		master.save_snapshot_state_now(master.get_accessed_pages());
	}

	/* Prefetching only the first 64KB leaves the rest to demand faults,
	   which must not change the outcome in any way. */
	auto options = snapshot_options(tinykvm::MachineOptions::Open);
	options.snapshot_prefetch_limit = 64UL * 1024;

	tinykvm::Machine restored { binary, options };
	REQUIRE(restored.has_snapshot_state());
	restored.set_printer([] (const char*, size_t) {}); /* quiet */
	restored.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(restored.return_value() == 1);

	unlink(SNAPSHOT_PATH);
}

TEST_CASE("Reorder snapshot memory in fault order", "[Snapshot]")
{
	const auto binary = build_and_load(GUEST_CODE);
	unlink(SNAPSHOT_PATH);

	uint64_t funcaddr = 0x0;
	{
		tinykvm::Machine master { binary,
			snapshot_options(tinykvm::MachineOptions::Create) };
		master.set_printer([] (const char*, size_t) {}); /* quiet */
		master.setup_linux({"snapshot"}, env);
		master.run(4.0f);
		funcaddr = master.address_of("bump");
		REQUIRE(funcaddr != 0x0);

		/* Record the order in which a request first touches each page, by
		   unpresenting every user page and letting the call fault them in. */
		std::vector<uint64_t> fault_order;
		master.make_unpresented_with_callback(
			[&fault_order] (uint64_t paddr, uint64_t /*vaddr*/) {
				fault_order.push_back(paddr);
			});

		/* Host-side reads of guest memory must still work while pages are
		   unpresented, and must not disturb the recorded fault order. */
		const uint64_t page = funcaddr & ~uint64_t(0xFFF);
		const size_t faults_before = fault_order.size();
		REQUIRE_NOTHROW(master.main_memory().get_userpage_at(page));
		REQUIRE(fault_order.size() == faults_before);

		master.timed_vmcall(funcaddr, 4.0f);
		master.restore_unpresented_pages();
		REQUIRE(!fault_order.empty());

		const auto populate = master.reorder_snapshot_memory(fault_order);
		REQUIRE(!populate.empty());
		REQUIRE(master.main_memory().memory_reordered);

		/* Reordering moves the page tables off the fixed root, which the
		   copy-on-write and fork machinery relies on. */
		REQUIRE_THROWS_AS(master.prepare_copy_on_write(1UL << 20),
			tinykvm::MachineException);

		master.save_snapshot_state_now(populate);
	}

	std::string output;
	tinykvm::Machine restored { binary,
		snapshot_options(tinykvm::MachineOptions::Open) };
	REQUIRE(restored.has_snapshot_state());
	REQUIRE(restored.main_memory().memory_reordered);
	restored.set_printer([&] (const char* data, size_t size) {
		output.append(data, size);
	});

	restored.timed_vmcall(funcaddr, 4.0f);
	REQUIRE(restored.return_value() == 2); /* the profiling call bumped it once */
	REQUIRE(output == "Hello Snapshot World");

	/* The restored VM is load-and-run only, just like the one it came from. */
	REQUIRE_THROWS_AS(restored.prepare_copy_on_write(1UL << 20),
		tinykvm::MachineException);

	unlink(SNAPSHOT_PATH);
}

TEST_CASE("Retries are not machine exceptions", "[Snapshot]")
{
	/* A RetryException is an internal page-walk signal. If it were a
	   MachineException, any broad handler would silently eat it. */
	REQUIRE_FALSE(std::is_base_of_v<tinykvm::MachineException,
		tinykvm::RetryException>);
}
