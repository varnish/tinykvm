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

	template <typename... Args>
	long vmcall(const char*, Args&&...);
	template <typename... Args> constexpr
	long vmcall(uint64_t addr, Args&&...);
	long run(unsigned timeout = 10);
	void stop();
	void reset();

	template <typename T>
	uint64_t stack_push(__u64& sp, const T&);
	uint64_t stack_push(__u64& sp, const void*, size_t);
	uint64_t stack_push(__u64& sp, const std::string&);

	tinykvm_x86regs registers() const;
	std::string_view io_data() const;
	std::string_view memory_at(uint64_t a, size_t s) const { return memory.view(a, s); }

	void system_call(unsigned);
	void install_syscall_handler(unsigned idx, syscall_t h) { m_syscalls.at(idx) = h; }
	void install_unhandled_syscall_handler(unhandled_syscall_t h) { m_unhandled_syscall = h; }

	uint64_t start_address() const noexcept { return this->m_start_address; }
	uint64_t stack_address() const noexcept { return this->m_stack_address; }

	uint64_t address_of(const char*) const;

	Machine(const std::vector<uint8_t>& binary, const MachineOptions&);
	Machine(std::string_view binary, const MachineOptions&);
	~Machine();

private:
	static constexpr uint64_t GDT_ADDR = 0x1600;
	static constexpr uint64_t IDT_ADDR = 0x1700;
	static constexpr uint64_t EXCEPT_ASM_ADDR = 0x2000;
	static constexpr uint64_t PT_ADDR  = 0x3000;
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
	void elf_loader(const MachineOptions&);
	void elf_load_ph(const MachineOptions&, const void*);
	void setup_long_mode();
	void print_registers();
	void handle_exception(uint8_t intr, const struct kvm_regs&);

	int   fd;
	bool  stopped = false;
	vCPU  vcpu;
	void* m_userdata = nullptr;

	std::array<syscall_t, TINYKVM_MAX_SYSCALLS> m_syscalls {nullptr};
	unhandled_syscall_t m_unhandled_syscall = [] (auto&, unsigned) {};

	std::string_view m_binary;
	uint64_t m_exit_address;
	uint64_t m_stack_address;
	uint64_t m_start_address;

	vMemory memory; // guest memory
	MemRange mmio_scall; // syscall MMIO slot
	MemRange ptmem; // page tables

	static int kvm_fd;
};

#include "machine_inline.hpp"
}
