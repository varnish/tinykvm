#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <vector>
#include <tinykvm/arm64/memory_layout.hpp>
#include <tinykvm/machine.hpp>

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

TEST_CASE("ARM64 raw guest exits through TinyKVM MMIO ABI", "[arm64]")
{
	try {
		tinykvm::Machine::init();
	} catch (const tinykvm::MachineException& e) {
		FAIL("Unable to initialize KVM for ARM64 raw guest test: "
			<< e.what() << " (" << e.data() << ")");
	}

	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	machine.copy_to_guest(CODE_ADDR, minimal_guest.data(),
		minimal_guest.size() * sizeof(minimal_guest[0]));

	auto regs = machine.registers();
	regs.pc = CODE_ADDR;
	regs.sp = STACK_ADDR;
	regs.pstate = 0x3c5;
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
	REQUIRE(out_regs.pc == CODE_ADDR + minimal_guest.size() * sizeof(minimal_guest[0]));
}
