#include <cstddef>
#include <cstdint>

struct vMemory {
	uint64_t physbase;
	char*  ptr;
	size_t size;

	void reset();
};
