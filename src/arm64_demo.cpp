#include <tinykvm/arm64/memory_layout.hpp>
#include <tinykvm/machine.hpp>

#include <array>
#include <cstdio>
#include <cstdint>
#include <vector>

static constexpr uint64_t MAX_MEMORY = 2ULL << 20;
static constexpr uint64_t CODE_ADDR = 0x100000;
static constexpr uint64_t DATA_ADDR = 0x101000;
static constexpr uint64_t STACK_ADDR = 0x180000;

int main()
{
	static const std::array<uint32_t, 4> guest {
		0x91001C24, // add x4, x1, #7
		0xF9000044, // str x4, [x2]
		0xAA0403E0, // mov x0, x4
		0xF9000060, // str x0, [x3]
	};

	try {
		tinykvm::Machine::init();

		const std::vector<uint8_t> empty_binary;
		tinykvm::Machine machine {empty_binary, { .max_mem = MAX_MEMORY }};
		machine.copy_to_guest(CODE_ADDR, guest.data(), guest.size() * sizeof(guest[0]));

		auto regs = machine.registers();
		regs.pc = CODE_ADDR;
		regs.sp = STACK_ADDR;
		regs.pstate = 0x3c0;
		regs.regs[1] = 35;
		regs.regs[2] = DATA_ADDR;
		regs.regs[3] = tinykvm::ARM64_STOP_MMIO_ADDR;
		machine.set_registers(regs);

		machine.run(1.0f);

		uint64_t result = 0;
		machine.copy_from_guest(&result, DATA_ADDR, sizeof(result));
		std::printf("ARM64 TinyKVM demo result: %lu\n", result);
		return result == 42 ? 0 : 1;
	} catch (const tinykvm::MachineException& e) {
		std::fprintf(stderr, "TinyKVM ARM64 demo failed: %s (%lu)\n", e.what(), e.data());
		return 1;
	}
}
