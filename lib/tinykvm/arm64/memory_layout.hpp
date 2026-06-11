#pragma once
#include <cstdint>

namespace tinykvm {
	static constexpr uint64_t VECTORS_ADDR = 0x8000;
	static constexpr uint64_t RET_STOP_ADDR = VECTORS_ADDR + 0x780;
	static constexpr uint64_t PT_ADDR  = 0x9000;
	static constexpr uint64_t PT_SIZE  = 0x5000;
	/* Reserved MMIO address used by raw ARM64 guests to request a stop. */
	static constexpr uint64_t ARM64_STOP_MMIO_ADDR = 0xF0000000;
	/* Reserved MMIO addresses used by the EL1 vector page. These GPAs must
	   stay outside guest RAM and be stage-1 mapped so KVM can exit on them. */
	static constexpr uint64_t ARM64_SYSCALL_MMIO_ADDR = 0xF0001000;
	static constexpr uint64_t ARM64_FATAL_MMIO_ADDR = 0xF0002000;

}
