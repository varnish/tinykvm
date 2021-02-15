#include "machine.hpp"
#include <cstring>

void vMemory::reset()
{
	std::memset(this->ptr, 0, this->size);
}
