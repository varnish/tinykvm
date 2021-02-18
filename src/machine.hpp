#pragma once
#include "forward.hpp"
#include "memory.hpp"
#include <string_view>
#include <vector>

namespace tinykvm {

struct Machine
{
	void setup_call(uint64_t rip, uint64_t rsp);
	long run(double timeout = 10.0);
	void reset();

	Machine(const std::vector<uint8_t>& binary, uint64_t max_mem);
	Machine(std::string_view binary, uint64_t max_mem);
	~Machine();

private:
	static constexpr uint64_t PT_ADDR  = 0x2000;
	static constexpr uint64_t IDT_ADDR = 0x1800;
	struct vCPU {
		void init(Machine&);

		int fd;
		struct kvm_run *kvm_run;
	};
	int install_memory(uint32_t idx, vMemory mem);
	void setup_long_mode();
	void setup_amd64_segments(struct kvm_sregs&);
	void setup_amd64_exceptions(struct kvm_sregs&, uint64_t ehandler);

	int fd;
	vCPU vcpu;
	vMemory memory; // guest memory
	MemRange mmio_scall; // syscall MMIO slot
	MemRange ptmem; // page tables
	MemRange romem; // binary + rodata
	MemRange rwmem; // stack + heap

	static int kvm_fd;
};

}
