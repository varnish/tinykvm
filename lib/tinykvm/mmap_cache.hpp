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
				return ((this->addr >= mem) && (this->addr + this->size <= mem + memsize))
					|| ((mem >= this->addr) && (mem + memsize <= this->addr + this->size));
			}
		};

		Range find(uint64_t size)
		{
			for (auto& r : m_lines)
			{
				if (!r.empty())
				{
					if (r.size >= size) {
						const auto ret = r;
						r = Range{};
						return ret;
					}
				}
			}
			return Range{};
		}

		void invalidate(uint64_t addr, uint64_t size)
		{
			for (auto& r : m_lines)
			{
				if (r.within(addr, size))
				{
					r = Range{};
				}
			}
		}

		void insert(uint64_t addr, uint64_t size)
		{
			m_lines[m_rotate].addr = addr;
			m_lines[m_rotate].size = size;

			m_rotate = (m_rotate + 1) % m_lines.size();
		}

	private:
		std::array<Range, 8> m_lines {};
		unsigned m_rotate = 0;
	};
} // tinykvm
