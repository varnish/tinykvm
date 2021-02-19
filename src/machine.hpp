#pragma once
#include "forward.hpp"
#include "memory.hpp"
#include <array>
#include <string_view>
#include <vector>

namespace tinykvm {

struct Machine
{
	using syscall_t = void(*)(Machine&);
	using unhandled_syscall_t = void(*)(Machine&, unsigned);

	void setup_call(uint64_t rip, uint64_t rsp);
	long run(double timeout = 10.0);
	void reset();

	void system_call(unsigned);
	void set_unhandled_syscall_handler(unhandled_syscall_t h) { m_unhandled_syscall = h; }

	uint64_t start_address() const noexcept { return romem.physbase; }

	Machine(const std::vector<uint8_t>& binary, uint64_t max_mem);
	Machine(std::string_view binary, uint64_t max_mem);
	~Machine();

private:
	static constexpr uint64_t PT_ADDR  = 0x2000;
	static constexpr uint64_t GDT_ADDR = 0x1600;
	static constexpr uint64_t IDT_ADDR = 0x1800;
	struct vCPU {
		void init(Machine&);
		void print_address_info(uint64_t addr);

		int fd;
		struct kvm_run *kvm_run;
	};
	int install_memory(uint32_t idx, vMemory mem);
	void setup_long_mode();
	void setup_amd64_exceptions(struct kvm_sregs&, uint64_t ehandler);
	void print_registers();
	void handle_exception(uint8_t);

	int fd;
	vCPU vcpu;
	vMemory memory; // guest memory
	MemRange mmio_scall; // syscall MMIO slot
	MemRange ptmem; // page tables
	MemRange romem; // binary + rodata
	MemRange rwmem; // stack + heap

	std::array<syscall_t, TINYKVM_MAX_SYSCALLS> m_syscalls {nullptr};
	unhandled_syscall_t m_unhandled_syscall = [] (auto&, unsigned) {};

	static int kvm_fd;
};

}
