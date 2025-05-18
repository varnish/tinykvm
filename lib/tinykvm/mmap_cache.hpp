#include <array>
#include <cstdint>

namespace tinykvm
{
	struct MMapCache
	{
		struct Range {
			uint64_t addr = 0x0;
			uint64_t size = 0u;

			constexpr bool empty() const noexcept { return size == 0u; }
			// Invalidate if one of the ranges is in the other (both ways!)
			constexpr bool overlaps(uint64_t mem, uint64_t memsize) const noexcept {
				return (mem + memsize > this->addr) && (mem < this->addr + this->size);
			}
			constexpr bool equals(uint64_t mem, uint64_t memsize) const noexcept {
				return (this->addr == mem) && (this->addr + this->size == mem + memsize);
			}
		};


		Range find(uint64_t size);

		const Range* find_collision(const std::vector<Range>& ranges, const Range& r);

		void invalidate(uint64_t addr, uint64_t size);

		void insert_free(uint64_t addr, uint64_t size);
		void insert_used(uint64_t addr, uint64_t size);
		void remove_used(uint64_t addr, uint64_t size);

		bool track_used_ranges() const noexcept { return m_track_used_ranges; }
		void set_track_used_ranges(bool track) noexcept { m_track_used_ranges = track; }

		const std::vector<Range>& free_ranges() const noexcept { return m_free_ranges; }
		const std::vector<Range>& used_ranges() const noexcept { return m_used_ranges; }
	private:
		std::vector<Range> m_free_ranges;
		std::vector<Range> m_used_ranges;
		bool m_track_used_ranges = true;
		size_t m_max_tracked_ranges = 4096;
	};
} // tinykvm
