#pragma once
#include <array>
#include <cstdint>

namespace tinykvm {
	static constexpr uint64_t VSYSCALL_AREA = 0xFFFF600000;

	const std::array<uint8_t, 4096>& vsys_page();
}
