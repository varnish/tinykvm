#include <catch2/catch_test_macros.hpp>

#include <cstring>
#include <string>
#include <utility>
#include <vector>
#include <memory>
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

// Issue fast-agent#94: executing a pooled (vm_group) fork on ARM64 used to
// block forever inside the nested KVM_RUN in arm64_flush_guest_tlb(). The
// arena grows upward from 2 GB and the MMIO exit window sits at 3.75 GB, so a
// group whose span reached 1.75 GB buried the window under its memslot --
// every exit store (STOP, syscall, fault report) then completed as a silent
// RAM write, and the first thing a member runs (the deferred TLB-flush stub,
// ticks = 0) wedged at `b .` with DAIF masked. The VmGroup constructor now
// walls the span below the window; this pins that, in the default-size shape
// that used to hang (B was 448 here before the wall, 74 after).
//
// NB: the guest function deliberately writes no memory -- a fork CoW-ing a
// 2 MB block without split_hugepages throws "l2 entry not writable" (#92),
// which is a separate defect and must not shadow this one.
TEST_CASE("ARM64 pooled fork executes a vmcall", "[arm64][vmgroup]")
{
	require_arm64_kvm();

	const auto [program, binary] = build_and_load(R"M(
int main() { return 0; }
extern int get_value() {
	return 42;
})M", "");

	tinykvm::Machine machine { binary, {
		.max_mem = MAX_MEMORY
	} };
	machine.setup_linux({"vmgroup"}, env);
	machine.run(8.0f);
	machine.prepare_copy_on_write();
	REQUIRE(machine.is_forkable());

	/* Control: the identical fork, unpooled, works. */
	{
		tinykvm::Machine fork { machine, {
			.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM
		} };
		const auto func = fork.address_of("get_value");
		REQUIRE(func != 0x0);
		fork.timed_vmcall(func, 8.0f);
		REQUIRE(fork.return_value() == 42);
	}

	/* The pooled twin of the control above. A B=2 group's arena spans 48 MB,
	   nowhere near the window: this half passed even before the wall. */
	{
		tinykvm::Machine fork { machine, {
			.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
			.vm_group = true, .vm_group_size = 2
		} };
		const auto func = fork.address_of("get_value");
		REQUIRE(func != 0x0);
		fork.timed_vmcall(func, 8.0f);
		REQUIRE(fork.return_value() == 42);
	}

	/* The shape that hung: default-sized groups (vm_group_size unset ->
	   DEFAULT_SIZE = 1024, walled by the host's vCPU cap and, now, by the MMIO
	   window), many members live at once, every one executed. */
	{
		std::vector<std::unique_ptr<tinykvm::Machine>> forks;
		for (int i = 0; i < 64; i++) {
			forks.push_back(std::make_unique<tinykvm::Machine>(machine,
				tinykvm::MachineOptions{
					.max_mem = MAX_MEMORY, .max_cow_mem = MAX_COWMEM,
					.vm_group = true
				}));
		}
		const auto func = forks.front()->address_of("get_value");
		REQUIRE(func != 0x0);
		for (size_t i = 0; i < forks.size(); i++) {
			forks[i]->timed_vmcall(func, 8.0f);
			REQUIRE(forks[i]->return_value() == 42);
		}
	}
}
