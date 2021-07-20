#pragma once
#include "common.hpp"
#include "forward.hpp"
#include "memory.hpp"
#include "memory_bank.hpp"
#include "threads.hpp"
#include <array>
#include <vector>

namespace tinykvm {

struct Machine
{
	using address_t = uint64_t;
	using syscall_t = void(*)(Machine&);
	using unhandled_syscall_t = void(*)(Machine&, unsigned);

	/* Setup Linux env and run through main */
	void setup_argv(const std::vector<std::string>& args,
					const std::vector<std::string>& env = {});
	void setup_linux(const std::vector<std::string>& args,
					const std::vector<std::string>& env = {});
	void run(unsigned timeout = 10);

	/* Make a function call into the VM */
	template <typename... Args>
	void vmcall(const char*, Args&&...);
	template <typename... Args> constexpr
	void vmcall(address_t, Args&&...);
	/* Retrieve optional return value from a vmcall */
	long return_value() const;

	void stop(bool = true);
	bool stopped() const noexcept { return m_stopped; }
	void reset_to(Machine&);

	/* When zeroes == true, new pages will be zeroed instead of duplicated */
	void copy_to_guest(address_t addr, const void*, size_t, bool zeroes = false);
	void copy_from_guest(void* dst, address_t addr, size_t);

	template <typename T>
	uint64_t stack_push(__u64& sp, const T&);
	uint64_t stack_push(__u64& sp, const void*, size_t);
	uint64_t stack_push(__u64& sp, const std::string&);

	/* Debugging */
	long step_one();
	long run_with_breakpoints(std::array<uint64_t, 4> bps);

	tinykvm_x86regs registers() const;
	void set_registers(const tinykvm_x86regs&);
	void get_special_registers(struct kvm_sregs&) const;
	void set_special_registers(const struct kvm_sregs&);
	std::pair<__u64, __u64> get_fsgs() const;
	void set_tls_base(__u64 baseaddr);
	void print_registers();

	static void install_syscall_handler(unsigned idx, syscall_t h) { m_syscalls.at(idx) = h; }
	static void install_unhandled_syscall_handler(unhandled_syscall_t h) { m_unhandled_syscall = h; }
	static auto get_syscall_handler(unsigned idx) { return m_syscalls.at(idx); }
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
	address_t exit_address() const noexcept;
	void set_stack_address(address_t addr) { this->m_stack_address = addr; }
	address_t max_address() const noexcept { return memory.physbase + memory.size; }

	uint64_t address_of(const char*) const;

	const auto& threads() const { return *m_mt; }
	auto& threads() { return *m_mt; }
	static void setup_multithreading();

	const auto& mmap() const { return m_mm; }
	auto& mmap() { return m_mm; }

	void install_memory(uint32_t idx, const VirtualMem&);
	void delete_memory(uint32_t idx);

	template <typename... Args> constexpr
	tinykvm_x86regs setup_call(uint64_t addr, Args&&... args);
	void prepare_copy_on_write();
	static void init();
	Machine(const std::vector<uint8_t>& binary, const MachineOptions&);
	Machine(std::string_view binary, const MachineOptions&);
	Machine(const Machine& other, const MachineOptions&);
	~Machine();

private:
	struct vCPU {
		void init(Machine&);
		void deinit();
		void print_address_info(uint64_t addr);
		tinykvm_x86regs registers() const;
		void assign_registers(const struct tinykvm_x86regs&);
		void get_special_registers(struct kvm_sregs&) const;
		void set_special_registers(const struct kvm_sregs&);

		int fd = 0;
		struct kvm_run *kvm_run = nullptr;
	};
	void reset_special_regs();
	void setup_registers(tinykvm_x86regs&);
	void setup_argv(__u64&, const std::vector<std::string>&, const std::vector<std::string>&);
	void setup_linux(__u64&, const std::vector<std::string>&, const std::vector<std::string>&);
	void elf_loader(const MachineOptions&);
	void elf_load_ph(const MachineOptions&, const void*);
	void relocate_section(const char* section_name, const char* sym_section);
	void setup_long_mode(const Machine* other);
	void handle_exception(uint8_t intr);
	long run_once();

	int   fd = 0;
	bool  m_stopped = true;
	bool  m_prepped = false;
	bool  m_forked = false;
	bool  m_userspaced = false;
	vCPU  vcpu;
	void* m_userdata = nullptr;

	static std::array<syscall_t, TINYKVM_MAX_SYSCALLS> m_syscalls;
	static unhandled_syscall_t m_unhandled_syscall;

	const std::string_view m_binary;
	uint64_t m_stack_address;
	uint64_t m_heap_address;
	uint64_t m_start_address;

	vMemory memory;  // guest memory

	uint64_t m_mm = 0;
	std::unique_ptr<MultiThreading> m_mt = nullptr;

	static int create_kvm_vm();
	static int kvm_fd;
};

#include "machine_inline.hpp"
}
