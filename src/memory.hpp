#include <cstddef>
#include <cstdint>

namespace tinykvm {

struct vMemory {
	uint64_t physbase;
	char*  ptr;
	size_t size;

	void reset();
	char* at(uint64_t addr) {
		//assert(addr - physbase < size);
		return &ptr[addr - physbase];
	}

	static vMemory New(uint64_t, size_t size);
	static vMemory NewMMIO(uint64_t, size_t size);
};

struct MemRange {
	uint64_t physbase;
	size_t   size;
	const char* name;

	bool within(uint64_t addr, size_t size = 0) const noexcept {
		return addr >= physbase && addr + size < physbase + size;
	}

	static MemRange New(const char*, uint64_t physical, size_t size);
};

}
