#include "machine.hpp"

namespace tinykvm {
constexpr uint64_t PageMask = vMemory::PageSize()-1;

MMapCache::Range MMapCache::find(uint64_t size)
{
	auto it = m_free_ranges.begin();
	while (it != m_free_ranges.end())
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
					m_free_ranges.erase(it);
				}
				return result;
			}
		}
		++it;
	}
	return Range{};
}

const MMapCache::Range* MMapCache::find_collision(const std::vector<Range>& ranges, const Range& r)
{
	for (auto& line : ranges)
	{
		if (line.overlaps(r.addr, r.size))
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
	auto it = m_free_ranges.begin();
	while (it != m_free_ranges.end())
	{
		const auto r = *it;
		if (r.overlaps(addr, size))
		{
			bool equals = r.equals(addr, size);
			it = m_free_ranges.erase(it);
			if (equals) return;
		}
		else ++it;
	}
}

void MMapCache::insert_free(uint64_t addr, uint64_t size)
{
	if (!m_free_ranges.empty()) {
		if (m_free_ranges.back().addr + m_free_ranges.back().size == addr) {
			m_free_ranges.back().size += size;
			return;
		}
		// Connect the free ranges if they are adjacent
		for (auto it = m_free_ranges.begin(); it != m_free_ranges.end(); ++it)
		{
			if (it->addr + it->size == addr)
			{
				it->size += size;
				return;
			}
			else if (it->addr == addr + size)
			{
				it->addr = addr;
				it->size += size;
				return;
			}
		}
	}
	if (m_free_ranges.size() >= m_max_tracked_ranges) {
		throw std::runtime_error("MMapCache: Too many free ranges");
	}
	m_free_ranges.push_back({addr, size});
}
void MMapCache::insert_used(uint64_t addr, uint64_t size)
{
	if (!m_used_ranges.empty()) {
		if (m_used_ranges.back().addr + m_used_ranges.back().size == addr) {
			m_used_ranges.back().size += size;
			return;
		}
	}
	if (m_used_ranges.size() >= m_max_tracked_ranges) {
		throw std::runtime_error("MMapCache: Too many used ranges");
	}
	m_used_ranges.push_back({addr, size});
}
void MMapCache::remove_used(uint64_t addr, uint64_t size)
{
	for (auto it = m_used_ranges.begin(); it != m_used_ranges.end();)
	{
		Range& r = *it;
		if (r.overlaps(addr, size))
		{
			if (addr <= r.addr && addr + size >= r.addr + r.size)
			{
				// The range fully overlaps the given range
				it = m_used_ranges.erase(it);
				continue;
			}
			else if (addr < r.addr)
			{
				// The removed range is below/before the given range
				// since it doesn't cover the whole range, we know that
				// the range remains and addr doesn't change
				r.size -= (addr + size) - r.addr;
				r.addr = addr + size;
				++it;
				continue;
			}
			else // addr >= r.addr
			{
				// The removed range is above the given range
				r.size = addr - r.addr;
				if (r.size == 0)
				{
					it = m_used_ranges.erase(it);
				}
				else
				{
					++it;
				}
				continue;
			}
			throw std::runtime_error("Unreachable");
		}
		else ++it;
	}
}

Machine::address_t Machine::mmap_allocate(size_t bytes)
{
	auto range = mmap_cache().find(bytes);
	if (!range.empty())
	{
		if (this->mmap_cache().track_used_ranges())
		{
			if (this->mmap_cache().find_collision(this->mmap_cache().used_ranges(), range))
			{
				throw std::runtime_error("MMapCache: Collision detected");
			}
			this->mmap_cache().insert_used(range.addr, range.size);
		}
		return range.addr;
	}

	const address_t result = this->m_mm;
	/* Bytes rounded up to nearest PAGE_SIZE. */
	this->m_mm += (bytes + PageMask) & ~PageMask;

	if (this->mmap_cache().track_used_ranges())
	{
		MMapCache::Range range { result, bytes };
		if (this->mmap_cache().find_collision(this->mmap_cache().used_ranges(), range))
		{
			throw std::runtime_error("MMapCache: Collision detected");
		}
		this->mmap_cache().insert_used(result, bytes);
	}
	return result;
}

bool Machine::mmap_unmap(uint64_t addr, size_t size)
{
	bool relaxed = false;
	if (addr + size > this->m_mm && addr < this->m_mm)
	{
		this->m_mm = (addr + PageMask) & ~PageMask;
		this->mmap_cache().invalidate(addr, size);
		relaxed = true;
	}
	else if (addr >= this->mmap_start())
	{
		// If relaxation didn't happen, put in the cache for later.
		this->mmap_cache().insert_free(addr, size);
	}
	if (this->mmap_cache().track_used_ranges())
	{
		this->mmap_cache().remove_used(addr, size);
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
