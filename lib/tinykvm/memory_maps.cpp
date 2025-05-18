#include "machine.hpp"

namespace tinykvm {
constexpr uint64_t PageMask = vMemory::PageSize()-1;

MMapCache::Range MMapCache::find(uint64_t size)
{
	auto it = m_lines.begin();
	while (it != m_lines.end())
	{
		auto& r = *it;
		if (!r.empty())
		{
			if (r.size >= size) {
				const Range result { r.addr, size };
				if (r.size > size) {
					r.addr += size;
					r.size -= size;
				} else {
					m_lines.erase(it);
				}
				return result;
			}
		}
		++it;
	}
	return Range{};
}

const MMapCache::Range* MMapCache::find_collision(const Range& r)
{
	for (auto& line : m_lines)
	{
		if (line.within(r.addr, r.size))
		{
			if (&r != &line)
			{
				// Collision with another range
				return &line;
			}
		}
	}
	return nullptr;
}

void MMapCache::invalidate(uint64_t addr, uint64_t size)
{
	auto it = m_lines.begin();
	while (it != m_lines.end())
	{
		const auto r = *it;
		if (r.within(addr, size))
		{
			bool equals = r.equals(addr, size);
			it = m_lines.erase(it);
			if (equals) return;
		}
		else ++it;
	}
}

void MMapCache::insert(uint64_t addr, uint64_t size)
{
	/* Extend the back range? */
	if (!m_lines.empty()) {
		if (m_lines.back().addr + m_lines.back().size == addr) {
			m_lines.back().size += size;
			return;
		}
	}

	m_lines.push_back({addr, size});
}

Machine::address_t Machine::mmap_allocate(size_t bytes)
{
	auto range = mmap_cache().find(bytes);
	if (!range.empty())
	{
		return range.addr;
	}

	const address_t result = this->m_mm;
	/* Bytes rounded up to nearest PAGE_SIZE. */
	this->m_mm += (bytes + PageMask) & ~PageMask;
	return result;
}

bool Machine::mmap_unmap(uint64_t addr, size_t size)
{
	bool relaxed = false;
	if (false && addr + size > this->m_mm && addr < this->m_mm)
	{
		this->m_mm = (addr + PageMask) & ~PageMask;
		this->mmap_cache().invalidate(addr, size);
		relaxed = true;
	}
	else if (addr >= this->mmap_start())
	{
		// If relaxation didn't happen, put in the cache for later.
		this->mmap_cache().insert(addr, size);
	}
	return relaxed;
}

bool Machine::mmap_relax(uint64_t addr, size_t size, size_t new_size)
{
	if (this->m_mm == addr + size && new_size <= size) {
		this->m_mm = (addr + new_size + PageMask) & ~PageMask;
		return true;
	}
	return false;
}

void Machine::do_mmap_callback(vCPU& cpu, address_t addr, size_t size,
	int prot, int flags, int fd, address_t offset)
{
	m_mmap_func(cpu, addr, size, prot, flags, fd, offset);
}

} // tinykvm
