#include <cstddef>
#include <cstdint>

namespace tinykvm {

struct vMemory {
	uint64_t physbase;
	char*  ptr;
	size_t size;
	const char* name;

	void reset();

	static vMemory New(const char*, uint64_t physical, size_t size);
};

}
