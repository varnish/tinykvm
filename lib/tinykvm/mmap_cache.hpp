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
			constexpr bool within(uint64_t mem, uint64_t memsize) const noexcept {
				return (mem + memsize > this->addr) && (mem < this->addr + this->size);
			}
			constexpr bool equals(uint64_t mem, uint64_t memsize) const noexcept {
				return (this->addr == mem) && (this->addr + this->size == mem + memsize);
			}
		};


		Range find(uint64_t size);

		const Range* find_collision(const Range& r);

		void invalidate(uint64_t addr, uint64_t size);

		void insert(uint64_t addr, uint64_t size);

	private:
		std::vector<Range> m_lines {};
	};
} // tinykvm
