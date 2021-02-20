#pragma once
#include "common.hpp"
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

	template <typename... Args> constexpr
	long vmcall(uint64_t addr, Args&&...);
	long run(unsigned timeout = 10);
	void stop();
	void reset();

	tinykvm_x86regs registers() const;
	std::string_view io_data() const;

	void system_call(unsigned);
	void install_syscall_handler(unsigned idx, syscall_t h) { m_syscalls.at(idx) = h; }
	void install_unhandled_syscall_handler(unhandled_syscall_t h) { m_unhandled_syscall = h; }

	uint64_t start_address() const noexcept { return romem.physbase; }
	uint64_t stack_address() const noexcept { return 0x0; }

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
		tinykvm_x86regs registers() const;
		void assign_registers(const struct tinykvm_x86regs&);

		int fd;
		struct kvm_run *kvm_run;
	};
	template <typename... Args> constexpr
	tinykvm_x86regs setup_call(uint64_t addr, Args&&... args);
	int install_memory(uint32_t idx, vMemory mem);
	void setup_long_mode();
	void print_registers();
	void handle_exception(uint8_t intr, const struct kvm_regs&);

	int   fd;
	bool  stopped = false;
	vCPU  vcpu;
	void* m_userdata = nullptr;

	std::array<syscall_t, TINYKVM_MAX_SYSCALLS> m_syscalls {nullptr};
	unhandled_syscall_t m_unhandled_syscall = [] (auto&, unsigned) {};

	vMemory memory; // guest memory
	MemRange mmio_scall; // syscall MMIO slot
	MemRange ptmem; // page tables
	MemRange romem; // binary + rodata
	MemRange rwmem; // stack + heap

	static int kvm_fd;
};

#include "machine_inline.hpp"
}
