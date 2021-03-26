#pragma once
#include "common.hpp"
#include "forward.hpp"
#include "memory.hpp"
#include "threads.hpp"
#include <array>
#include <vector>

namespace tinykvm {

struct Machine
{
	using address_t = uint64_t;
	using syscall_t = void(*)(Machine&);
	using unhandled_syscall_t = void(*)(Machine&, unsigned);
	static constexpr address_t HIGHMEM_TRESHOLD = 0x100000000;

	template <typename... Args>
	long vmcall(const char*, Args&&...);
	template <typename... Args> constexpr
	long vmcall(address_t, Args&&...);

	void setup_argv(const std::vector<std::string>& args,
					const std::vector<std::string>& env = {});
	void setup_linux(const std::vector<std::string>& args,
					const std::vector<std::string>& env = {});
	long run(unsigned timeout = 10);
	long step_one();
	long run_with_breakpoints(std::array<uint64_t, 4> bps);
	void stop(bool = true);
	bool stopped() const noexcept { return m_stopped; }
	void reset();

	void copy_to_guest(address_t addr, const void*, size_t);

	template <typename T>
	uint64_t stack_push(__u64& sp, const T&);
	uint64_t stack_push(__u64& sp, const void*, size_t);
	uint64_t stack_push(__u64& sp, const std::string&);

	tinykvm_x86regs registers() const;
	void set_registers(const tinykvm_x86regs&);
	void get_special_registers(struct kvm_sregs&) const;
	std::pair<__u64, __u64> get_fsgs() const;
	void set_tls_base(__u64 baseaddr);
	void print_registers();

	void install_syscall_handler(unsigned idx, syscall_t h) { m_syscalls.at(idx) = h; }
	void install_unhandled_syscall_handler(unhandled_syscall_t h) { m_unhandled_syscall = h; }
	auto get_syscall_handler(unsigned idx) const { return m_syscalls.at(idx); }
	void system_call(unsigned);

	std::string_view io_data() const;
	std::string_view memory_at(uint64_t a, size_t s) const;
	template <typename T = char>
	T* rw_memory_at(uint64_t a, size_t s);
	bool memory_safe_at(uint64_t a, size_t s) const;
	char* unsafe_memory_at(uint64_t a, size_t s) { return memory.at(a, s); }
	uint64_t translate(uint64_t virt) const;

	address_t start_address() const noexcept { return this->m_start_address; }
	address_t stack_address() const noexcept { return this->m_stack_address; }
	address_t heap_address() const noexcept { return this->m_heap_address; }
	address_t exit_address() const noexcept { return this->m_exit_address; }
	void set_exit_address(address_t addr) { this->m_exit_address = addr; }
	address_t max_address() const noexcept { return memory.physbase + memory.size; }

	uint64_t address_of(const char*) const;

	const auto& threads() const { return *m_mt; }
	auto& threads() { return *m_mt; }
	void setup_multithreading();

	Machine(const std::vector<uint8_t>& binary, const MachineOptions&);
	Machine(std::string_view binary, const MachineOptions&);
	~Machine();

private:
	struct vCPU {
		void init(Machine&);
		void print_address_info(uint64_t addr);
		tinykvm_x86regs registers() const;
		void assign_registers(const struct tinykvm_x86regs&);
		void get_special_registers(struct kvm_sregs&) const;

		int fd;
		struct kvm_run *kvm_run;
	};
	template <typename... Args> constexpr
	tinykvm_x86regs setup_call(uint64_t addr, Args&&... args);
	void setup_registers(tinykvm_x86regs&);
	void setup_argv(__u64&, const std::vector<std::string>&, const std::vector<std::string>&);
	void setup_linux(__u64&, const std::vector<std::string>&, const std::vector<std::string>&);
	int install_memory(uint32_t idx, vMemory mem);
	void elf_loader(const MachineOptions&);
	void elf_load_ph(const MachineOptions&, const void*);
	void relocate_section(const char* section_name, const char* sym_section);
	void setup_long_mode();
	void handle_exception(uint8_t intr);
	long run_once();

	int   fd;
	bool  m_stopped = false;
	vCPU  vcpu;
	void* m_userdata = nullptr;

	std::array<syscall_t, TINYKVM_MAX_SYSCALLS> m_syscalls {nullptr};
	unhandled_syscall_t m_unhandled_syscall = [] (auto&, unsigned) {};

	std::string_view m_binary;
	uint64_t m_exit_address;
	uint64_t m_stack_address;
	uint64_t m_heap_address;
	uint64_t m_start_address;

	vMemory memory; // guest memory
	vMemory vsyscall; // vsyscall page
	MemRange mmio_scall; // syscall MMIO slot
	MemRange ptmem; // page tables

	std::unique_ptr<MultiThreading> m_mt = nullptr;

	static int kvm_fd;
};

#include "machine_inline.hpp"
}
