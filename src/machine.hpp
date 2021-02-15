#pragma once
#include "forward.hpp"
#include "memory.hpp"
#include <span>

namespace tinykvm {

struct Machine
{
	void setup_call(uint64_t rip, uint64_t rsp);
	long run(double timeout = 10.0);
	void reset();

	Machine(std::span<const uint8_t> binary, uint64_t max_mem);
	~Machine();

private:
	struct vCPU {
		void init(Machine&);

		int fd;
		struct kvm_run *kvm_run;
	};
	int install_memory(uint32_t idx, vMemory mem);
	void setup_long_mode();
	void setup_amd64_segments(struct kvm_sregs&);

	int fd;
	vCPU vcpu;
	vMemory ptmem; // page tables
	vMemory romem; // binary + rodata
	vMemory rwmem; // stack + heap

	static int kvm_fd;
};

}
