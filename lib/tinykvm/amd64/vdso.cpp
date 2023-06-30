#include "vdso.hpp"

namespace tinykvm {

__attribute__((aligned(4096)))
static const std::array<uint8_t, 4096> vsys = {
	0x66, 0xb8, 0x60, 0x00, 0x66, 0xe7, 0x00, 0xc3
};

const std::array<uint8_t, 4096>& vsys_page() {
	return vsys;
}

} // tinykvm
