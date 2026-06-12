#pragma once
#include "../paging.hpp"

namespace tinykvm {
	struct Machine;
	struct vCPU;

	void arm64_setup_el1_mmu(Machine&, vCPU&);
}
