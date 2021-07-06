#include "machine.hpp"

#include <cstring>

namespace tinykvm {

void Machine::copy_to_guest(address_t addr, const void* vsrc, size_t len, bool zeroes)
{
	if (m_forked)
	{
		auto* src = (const uint8_t *)vsrc;
		while (len != 0)
		{
			const size_t offset = addr & (vMemory::PAGE_SIZE-1);
			const size_t size = std::min(vMemory::PAGE_SIZE - offset, len);
			auto* page = memory.get_writable_page(addr & ~0xFFF, zeroes);
			std::copy(src, src + size, &page[offset]);

			addr += size;
			src += size;
			len -= size;
		}
		return;
	}
	/* Original VM uses identity-mapped memory */
	auto* dst = memory.safely_at(addr, len);
	std::memcpy(dst, vsrc, len);
}

void Machine::copy_from_guest(void* dst, address_t addr, size_t size)
{
	auto* src = memory.safely_at(addr, size);
	std::memcpy(dst, src, size);
}

} // tinykvm
