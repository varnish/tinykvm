#pragma once
#include <array>
#include <cstdint>

namespace tinykvm {
	static constexpr uint64_t VSYSCALL_AREA = 0xFFFFFFFFFF600000;

	const std::array<uint8_t, 4096>& vdso_page();
}
