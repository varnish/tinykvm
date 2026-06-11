#include <catch2/catch_test_macros.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <string_view>
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
	REQUIRE(out_regs.pc == CODE_ADDR + (minimal_guest.size() - 1) * sizeof(minimal_guest[0]));
}

TEST_CASE("ARM64 SVC guest exits through TinyKVM syscall MMIO ABI", "[arm64]")
{
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
	regs.pstate = 0x3c5;
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
	REQUIRE(machine.registers().pc == CODE_ADDR + (syscall_guest.size() - 1) * sizeof(syscall_guest[0]));
}

TEST_CASE("ARM64 vmcall returns through LR stop stub", "[arm64]")
{
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
	const std::vector<uint8_t> empty_binary;
	tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
	__u64 sp = STACK_ADDR;
	const uint64_t addr = machine.stack_push_cstr(sp, "tiny");
	char buffer[5] {};
	machine.copy_from_guest(buffer, addr, sizeof(buffer));
	REQUIRE(std::string_view(buffer, sizeof(buffer)) == std::string_view("tiny\0", 5));
}
