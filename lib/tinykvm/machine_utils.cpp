#include "machine.hpp"

#include "kernel/amd64.hpp"
#include "kernel/paging.hpp"
#include <cstring>

namespace tinykvm {

void Machine::copy_to_guest(address_t addr, const void* vsrc, size_t len)
{
	if (m_forked)
	{
		auto* src = (const uint8_t *)vsrc;
		while (len != 0)
		{
			const size_t offset = addr & (PAGE_SIZE-1);
			const size_t size = std::min(PAGE_SIZE - offset, len);
			auto* page = get_writable_page(memory, addr & ~0xFFF,
				[this] () -> void* {
					return memory.banks.get_page();
				});
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

char* get_writable_page(vMemory&, uint64_t addr, page_allocator_t)
{
	/** TODO:
	 * 1. Allocate memory bank page
	 * 2. Get memory bank page physical address
	 * 3. Recursively copy page tables
	 * 4. Mark final entry as user-read-write-present
	 **/
	return nullptr;
}

} // tinykvm
