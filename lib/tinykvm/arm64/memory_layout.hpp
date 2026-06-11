#pragma once
#include <cstdint>

namespace tinykvm {
	static constexpr uint64_t PT_ADDR  = 0x9000;
	/* Reserved MMIO address used by raw ARM64 guests to request a stop. */
	static constexpr uint64_t ARM64_STOP_MMIO_ADDR = 0x10000000;

}
