#include "machine.hpp"

namespace tinykvm {
static constexpr size_t MMAP_COLLISION_TRESHOLD = 512ULL << 20; // 512MB
static constexpr uint64_t PageMask = vMemory::PageSize()-1;
static constexpr bool VERBOSE_MMAP_CACHE = false;

MMapCache::Range MMapCache::find(uint64_t size)
{
	auto it = m_free_ranges.begin();
	while (it != m_free_ranges.end())
	{
		auto& r = *it;
		if (r.size >= size) {
			const Range result { r.addr, size };
			if (r.size > size) {
				r.addr += size;
				r.size -= size;
			} else {
				m_free_ranges.erase(it);
			}
			if constexpr (VERBOSE_MMAP_CACHE)
				printf("MMapCache: Found free range %lx %lx\n", result.addr, result.addr + result.size);
			return result;
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
			// Collision with another range
			return &line;
		}
	}
	return nullptr;
}

void MMapCache::insert_free(uint64_t addr, uint64_t size)
{
	if (addr + size > current())
	{
		throw MachineException("MMapCache: Invalid free range");
	}
	if constexpr (VERBOSE_MMAP_CACHE)
		printf("MMapCache: Inserting free range %lx %lx\n", addr, addr + size);

	// Check for collisions with other ranges
	if (find_collision(m_free_ranges, { addr, size }))
	{
		throw MachineException("MMapCache: Collision detected");
	}
	// Connect existing ranges if they are adjacent
	for (Range& free_range : m_free_ranges)
	{
		if (free_range.addr + free_range.size == addr)
		{
			if constexpr (VERBOSE_MMAP_CACHE)
				printf("MMapCache: Merging free range *above* %lx %lx with result %lx %lx\n",
					free_range.addr, free_range.addr + free_range.size,
					free_range.addr, free_range.addr + free_range.size + size);

			free_range.size += size;
			return;
		}
		//else if (free_range.addr == addr + size)
		//{
		//	if constexpr (VERBOSE_MMAP_CACHE)
		//		printf("MMapCache: Merging free range *below* %lx %lx with result %lx %lx\n",
		//			free_range.addr, free_range.addr + free_range.size,
		//			addr, addr + size + free_range.size);
		//	free_range.addr = addr;
		//	free_range.size += size;
		//	return;
		//}
	}

	if (m_free_ranges.size() >= m_max_tracked_ranges) {
		throw MachineException("MMapCache: Too many free ranges");
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
		throw MachineException("MMapCache: Too many used ranges");
	}
	m_used_ranges.push_back({addr, size});
}

void MMapCache::remove(uint64_t addr, uint64_t size, std::vector<Range>& ranges)
{
	for (auto it = ranges.begin(); it != ranges.end();)
	{
		Range& r = *it;
		if (r.overlaps(addr, size))
		{
			if (addr <= r.addr && addr + size >= r.addr + r.size)
			{
				// The range fully overlaps the given range
				it = ranges.erase(it);
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
					it = ranges.erase(it);
				}
				else
				{
					++it;
				}
				continue;
			}
			throw MachineException("Unreachable");
		}
		else ++it;
	}
	if (find_collision(ranges, { addr, size }))
	{
		throw MachineException("MMapCache: Failed to remove range");
	}
}
void MMapCache::remove_free(uint64_t addr, uint64_t size)
{
	remove(addr, size, m_free_ranges);
}
void MMapCache::remove_used(uint64_t addr, uint64_t size)
{
	remove(addr, size, m_used_ranges);
}

Machine::address_t Machine::mmap_allocate(size_t bytes)
{
	bytes = (bytes + PageMask) & ~PageMask;

	auto range = mmap_cache().find(bytes);
	if (!range.empty())
	{
		if (UNLIKELY(range.addr < this->mmap_start())) {
			throw MachineException("MMapCache: Invalid range (below mmap_start)", range.addr);
		}
		else if (UNLIKELY(range.addr + range.size > this->mmap_cache().current())) {
			throw MachineException("MMapCache: Invalid range (exceeds current address)", range.addr);
		}

		if (this->mmap_cache().track_used_ranges())
		{
			if (this->mmap_cache().find_collision(this->mmap_cache().used_ranges(), range))
			{
				throw MachineException("MMapCache: Collision detected");
			}
			this->mmap_cache().insert_used(range.addr, range.size);
		}
		return range.addr;
	}

	const address_t result = this->mmap_cache().current();
	/* Bytes rounded up to nearest PAGE_SIZE. */
	this->mmap_cache().current() += bytes;

	if (this->mmap_cache().track_used_ranges())
	{
		MMapCache::Range range { result, bytes };
		if (this->mmap_cache().find_collision(this->mmap_cache().used_ranges(), range))
		{
			throw MachineException("MMapCache: Collision detected", result);
		}
		this->mmap_cache().insert_used(result, bytes);
	}
	return result;
}

Machine::address_t Machine::mmap_fixed_allocate(uint64_t addr, size_t bytes)
{
	if (UNLIKELY(addr < this->mmap_start())) {
		throw MachineException("MMapCache: Invalid range (below mmap_start)", addr);
	} else if (UNLIKELY(addr + bytes > this->mmap_cache().current())) {
		throw MachineException("MMapCache: Invalid range (exceeds current address)", addr);
	}

	bytes = (bytes + PageMask) & ~PageMask;

	// Make sure there is no free range in the way
	mmap_cache().remove_free(addr, bytes);

	if (this->mmap_cache().track_used_ranges())
	{
		MMapCache::Range range { addr, bytes };
		// Only insert the range if it doesn't collide with any other used ranges
		// as this is a fixed mapping, which can be placed anywhere.
		if (this->mmap_cache().find_collision(this->mmap_cache().used_ranges(), range) == nullptr)
		{
			this->mmap_cache().insert_used(addr, bytes);
		}
	}

	// If the mapping is within a certain range, we should adjust
	// the current mmap address to the end of the new mapping. This is
	// to avoid future collisions when allocating.
	if (mmap_cache().current() < addr + bytes)
	{
		if (addr < mmap_cache().current() + MMAP_COLLISION_TRESHOLD)
		{
			const uint64_t current_addr = mmap_cache().current();
			// Adjust the current mmap address to the end of the new mapping
			mmap_cache().current() = addr + bytes;
			// Insert the unused area between the current mmap address and the new mapping
			const size_t unused_size = addr - current_addr;
			if (unused_size > 0) {
				mmap_cache().insert_free(current_addr, unused_size);
			}
			if constexpr (VERBOSE_MMAP_CACHE)
				printf("MMapCache: Adjusting current mmap address to %lx\n", mmap_cache().current());
		}
	}

	// Simply return the address
	return addr;
}

bool Machine::mmap_unmap(uint64_t addr, size_t size)
{
	bool relaxed = false;
	if (addr + size == this->mmap_cache().current() && addr < this->mmap_cache().current())
	{
		this->mmap_cache().remove_free(addr, size);
		this->mmap_cache().current() = (addr + PageMask) & ~PageMask;
		relaxed = true;
	}
	else if (addr >= this->heap_address())
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

Machine::address_t Machine::mmap_current() const noexcept
{
	return this->mmap_cache().current();
}

bool Machine::mmap_relax(uint64_t addr, size_t size, size_t new_size)
{
	if (this->mmap_cache().current() == addr + size && new_size <= size) {
		this->mmap_cache().current() = (addr + new_size + PageMask) & ~PageMask;
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
