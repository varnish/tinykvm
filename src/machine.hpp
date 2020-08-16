#pragma once
#include <cstdint>
#include <vector>

namespace tinykvm
{

struct Machine
{
	Machine(const std::vector<uint8_t>& binary);

	void run(double timeout);

};

}
