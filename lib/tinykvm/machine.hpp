#pragma once
#include "common.hpp"
#include "memory.hpp"
#include "memory_bank.hpp"
#include "mmap_cache.hpp"
#include "linux/fds.hpp"
#include "linux/signals.hpp"
#include "vcpu.hpp"
#include <array>
#include <cassert>
#include <functional>
#include <memory>
#include <span>
#include <vector>

namespace tinykvm {

struct Machine
{
	using address_t = uint64_t;
	using syscall_t = void(*)(vCPU&);
	using numbered_syscall_t = void(*)(vCPU&, unsigned);
	using io_callback_t = void(*)(vCPU&, unsigned, unsigned);
	using printer_func = std::function<void(const char*, size_t)>;
	using mmap_func_t = std::function<void(vCPU&, address_t, size_t, int, int, int, address_t)>;

	/* Setup Linux env and run through main */
	void setup_argv(const std::vector<std::string>& args,
					const std::vector<std::string>& env = {});
	void setup_linux(const std::vector<std::string>& args,
					const std::vector<std::string>& env = {});
	void run(float timeout_secs = 0.f);
	void run_in_usermode(float timeout_secs = 0.f);
	void enter_usermode();

	/* Make a SYSV function call into the VM, with no timeout */
	template <typename... Args>
	void vmcall(const char*, Args&&...);
	template <typename... Args> constexpr
	void vmcall(address_t, Args&&...);
	/* SYSV function call with timeout */
	template <typename... Args> constexpr
	void timed_vmcall(address_t, float timeout, Args&&...);
	template <typename... Args> constexpr
	void timed_vmcall_stack(address_t, address_t stk, float timeout, Args&&...);
	/* Retrieve optional return value from a vmcall */
	long return_value() const;
	/* Resume the VM from a paused state */
	void vmresume(float timeout_secs = 0.f);

	auto& cpu() noexcept { return this->vcpu; }
	const auto& cpu() const noexcept { return this->vcpu; }

	bool is_forkable() const noexcept { return m_prepped; }
	void stop(bool = true);
	bool stopped() const noexcept { return vcpu.stopped; }
	bool reset_to(const Machine&, const MachineOptions&); // true = full reset
	void reset_to(std::string_view binary, const MachineOptions&);

	/* When zeroes == true, new pages will be zeroed instead of duplicated */
	void copy_to_guest(address_t addr, const void*, size_t, bool zeroes = false);
	void copy_from_guest(void* dst, address_t addr, size_t) const;
	void unsafe_copy_from_guest(void* dst, address_t addr, size_t) const;
	/* Fill an array of buffers pointing to complete guest virtual [addr, len].
	   Throws an exception if there was a protection violation.
	   Returns the number of buffers filled, or an exception if not enough. */
	struct Buffer { const char* ptr; size_t len; };
	size_t gather_buffers_from_range(size_t cnt, Buffer[], address_t addr, size_t len) const;
	size_t gather_buffers_from_range(std::vector<Buffer>&, address_t addr, size_t len) const;
	/* Same as above, but all buffers have pre-allocated writable pages. */
	struct WrBuffer { char* ptr; size_t len; };
	size_t writable_buffers_from_range(std::vector<WrBuffer>&, address_t addr, size_t len);
	/* Lazily create CoW mmap-backed area from an open file descriptor, return the mmap pointer */
	bool mmap_backed_area(int fd, int off, int prot, address_t dst, size_t size);
	bool has_mmap_backed_area(int fd, int off, address_t addr, size_t size) const;
	/* Build std::string from zero-terminated memory. */
	std::string copy_from_cstring(address_t src, size_t maxlen = 65535u) const;
	/* Build std::string from buffer, length in memory. */
	std::string buffer_to_string(address_t src, size_t len, size_t maxlen = 65535u) const;
	/* Explicitly zero memory range. */
	void memzero(address_t src, size_t len);
	/* View sequential user-writable memory as a string_view, or throw an exception. Small
		structs can be viewed provided the guest over-aligns so that it never crosses a page. */
	std::span<uint8_t> writable_memview(address_t src, size_t len);
	/* View sequential user-writable memory as an array of T, or throw an exception. */
	template <typename T>
	T* writable_memarray(address_t src, size_t elements = 1) {
		return reinterpret_cast<T*>(writable_memview(src, elements * sizeof(T)).data());
	}
	/* Build a std::string from a zero-terminated string in memory. */
	std::string memcstring(address_t src, size_t maxlen = 65535u) const;

	struct StringOrView {
		const char* begin() const noexcept { return sv.begin(); }
		const char* end() const noexcept { return sv.end(); }
		const char* c_str() const noexcept { return sv.begin(); }
		size_t size() const noexcept { return sv.size(); }

		bool is_sequential() const noexcept { return str.empty(); }

		explicit StringOrView(std::string_view strview) : sv{strview} {}
		explicit StringOrView(std::string s) : str{std::move(s)}, sv{str} {}

		std::string str;
		std::string_view sv;
	};
	/* Helper to avoid allocating string. */
	StringOrView string_or_view(address_t src, size_t size) const;
	/* Calls string_view when memory is sequential, otherwise builds string. */
	void string_or_view(address_t src, size_t size, std::function<void(std::string_view)>, std::function<void(std::string)>) const;

	/* Call function with each segment of memory in given buffer. */
	void foreach_memory(address_t src, size_t size, std::function<void(const std::string_view)>) const;
	/* Efficiently copy between machines */
	void copy_from_machine(address_t dst, Machine& src, address_t sa, size_t size);

	template <typename T>
	uint64_t stack_push(__u64& sp, const T&);
	uint64_t stack_push(__u64& sp, const void*, size_t);
	uint64_t stack_push(__u64& sp, const std::string&);
	uint64_t stack_push_cstr(__u64& sp, const char*);
	uint64_t stack_push_cstr(__u64& sp, const char*, size_t);
	template <typename T>
	uint64_t stack_push_std_array(__u64& sp, const T&, size_t N = T::size());

	/* Debugging */
	long step_one();
	long run_with_breakpoints(std::array<uint64_t, 4> bps);

	tinykvm_x86regs& registers();
	const tinykvm_x86regs& registers() const;
	void set_registers(const tinykvm_x86regs&);
	tinykvm_fpuregs fpu_registers() const;
	void set_fpu_registers(const tinykvm_fpuregs&);
	const kvm_sregs& get_special_registers() const;
	void set_special_registers(const kvm_sregs&);
	std::pair<__u64, __u64> get_fsgs() const;
	void set_tls_base(__u64 baseaddr);

	static void install_syscall_handler(unsigned idx, syscall_t h) { m_syscalls.at(idx) = h; }
	static void install_unhandled_syscall_handler(numbered_syscall_t h) { m_unhandled_syscall = h; }
	static auto get_syscall_handler(unsigned idx) { return m_syscalls.at(idx); }
	void system_call(vCPU&, unsigned no);
	static void install_input_handler(io_callback_t h) { m_on_input = h; }
	static void install_output_handler(io_callback_t h) { m_on_output = h; }

	template <typename T> void set_userdata(T* data) { m_userdata = data; }
	template <typename T> T* get_userdata() { return static_cast<T*> (m_userdata); }

	std::string_view memory_at(uint64_t a, size_t s) const;
	template <typename T = char>
	T* rw_memory_at(uint64_t a, size_t s);
	bool memory_safe_at(uint64_t a, size_t s) const;
	char* unsafe_memory_at(uint64_t a, size_t s) { return memory.at(a, s); }
	uint64_t translate(uint64_t virt) const;

	bool is_dynamic() const noexcept { return m_image_base != 0x0; }
	address_t image_base() const noexcept { return this->m_image_base; }
	address_t start_address() const noexcept { return this->m_start_address; }
	address_t stack_address() const noexcept { return this->m_stack_address; }
	address_t heap_address() const noexcept { return this->m_heap_address; }
	address_t entry_address() const noexcept;
	address_t preserving_entry_address() const noexcept;
	address_t exit_address() const noexcept;
	void set_stack_address(address_t addr) { this->m_stack_address = addr; }
	address_t kernel_end_address() const noexcept { return m_kernel_end; }
	address_t max_address() const noexcept { return memory.physbase + memory.size; }

	static constexpr uint64_t BRK_MAX = 0x22000;
	address_t brk_address() const noexcept { return this->m_brk_address; }
	address_t brk_end_address() const noexcept { return this->m_brk_end_address; }
	void set_brk_address(address_t addr) { this->m_brk_address = addr; }
	address_t mmap_start() const noexcept { return this->m_heap_address; }
	address_t mmap_current() const noexcept;
	address_t mmap_allocate(size_t bytes, int prot = 0x3, bool huge = false);
	address_t mmap_fixed_allocate(uint64_t addr, size_t bytes, bool is_fixed, int prot = 0x3);
	bool      mmap_unmap(uint64_t addr, size_t size);
	bool relocate_fixed_mmap() const noexcept { return m_relocate_fixed_mmap; }
	bool mmap_relax(uint64_t addr, size_t size, size_t new_size);
	void do_mmap_callback(vCPU&, address_t, size_t, int, int, int, address_t);
	void set_mmap_callback(mmap_func_t f) { m_mmap_func = std::move(f); }

	uint64_t address_of(const char*) const;
	std::string resolve(uint64_t rip, std::string_view binary = {}) const;

	bool smp_active() const noexcept;
	int  smp_active_count() const noexcept;
	void smp_wait();
	const struct SMP& smp() const;
	struct SMP& smp();

	/* Multi-threading */
	bool has_threads() const noexcept { return m_mt != nullptr; }
	const struct MultiThreading& threads() const;
	struct MultiThreading& threads();
	static void setup_multithreading();

	/* Memory maps */
	const auto& mmap_cache() const noexcept { return m_mmap_cache; }
	auto& mmap_cache() noexcept { return m_mmap_cache; }

	/* Signal structure, lazily created */
	Signals& signals();
	SignalAction& sigaction(int sig);

	/* File descriptors, lazily created */
	FileDescriptors& fds();
	const FileDescriptors& fds() const;

	void set_printer(printer_func pf = m_default_printer) { m_printer = std::move(pf); }
	void print(const char*, size_t);
	void print_registers() const { vcpu.print_registers(); }
	void print_pagetables() const;
	void print_exception_handlers() const;
	struct RemoteGDBOptions {
		std::string gdb_path = "/usr/bin/gdb";
		std::string command = "bt";
		bool verbose = false;
		bool quit = false;
	};
	void print_remote_gdb_backtrace(const std::string& filename, const RemoteGDBOptions& opts);

	void install_memory(uint32_t idx, const VirtualMem&, bool ro);
	void delete_memory(uint32_t idx);
	vMemory& main_memory() noexcept;
	const vMemory& main_memory() const noexcept;
	std::string_view binary() const noexcept { return m_binary; }

	/* The extra used memory attached to a VM for copy-on-write mechanisms. */
	size_t banked_memory_pages() const noexcept;
	size_t banked_memory_bytes() const noexcept { return banked_memory_pages() * vMemory::PageSize(); }
	/* The extra memory capacity attached to a VM for copy-on-write mechanisms. */
	size_t banked_memory_allocated_pages() const noexcept; // How many pages out of the capacity are allocated (backed by memory)
	size_t banked_memory_allocated_bytes() const noexcept { return banked_memory_allocated_pages() * vMemory::PageSize(); }
	size_t banked_memory_capacity_pages() const noexcept; // How many pages is the VM allowed to allocate in total
	size_t banked_memory_capacity_bytes() const noexcept { return banked_memory_capacity_pages() * vMemory::PageSize(); }

	template <typename... Args> constexpr
	void setup_call(tinykvm_x86regs&, uint64_t addr, uint64_t rsp, Args&&... args);
	void setup_clone(tinykvm_x86regs&, address_t stack);
	/* Make VM copy-on-write in order to support fast forking.
	   When @max_work_mem is non-zero, the master VM can still
	   be used after preparation. */
	void prepare_copy_on_write(size_t max_work_mem = 0, uint64_t shared_memory_boundary = UINT64_MAX);
	void set_main_memory_writable(bool v) { memory.main_memory_writes = v; }
	bool is_forked() const noexcept { return m_forked; }
	bool uses_cow_memory() const noexcept { return m_forked || m_prepped; }

	/* Remote VM through address space merging */
	void remote_connect(Machine& other, bool connect_now = true);
	address_t remote_activate_now();
	address_t remote_disconnect();
	bool is_remote_connected() const noexcept { return m_remote != nullptr; };
	address_t remote_base_address() const noexcept;
	const Machine& remote() const;
	Machine& remote();

	/* Profiling */
	MachineProfiling* profiling() noexcept { return m_profiling.get(); }
	const MachineProfiling* profiling() const noexcept { return m_profiling.get(); }
	bool is_profiling() const noexcept { return m_profiling != nullptr; }
	void set_profiling(bool enable) {
		if (enable && m_profiling == nullptr) {
			m_profiling.reset(new MachineProfiling);
		} else if (!enable) {
			m_profiling.reset();
		}
	}

	/// @brief Enable/disable verbose system calls. When enabled, every system call
	/// will be printed to the console, in a trace-like format.
	/// @param verbose True to enable verbose system calls, false to disable it.
	void set_verbose_system_calls(bool verbose) noexcept {
		m_verbose_system_calls = verbose;
	}
	/// @brief Enable/disable verbose mmap calls. When enabled, every mmap
	/// syscall will be printed to the console, in a trace-like format.
	/// @param verbose True to enable verbose mmap syscalls, false to disable it.
	void set_verbose_mmap_syscalls(bool verbose) noexcept {
		m_verbose_mmap_syscalls = verbose;
	}
	/// @brief Enable/disable verbose thread syscalls. When enabled, every thread
	/// syscall will be printed to the console, in a trace-like format.
	/// @param verbose True to enable verbose thread syscalls, false to disable it.
	void set_verbose_thread_syscalls(bool verbose) noexcept {
		m_verbose_thread_syscalls = verbose;
	}

	/* Migrates the VM to the current thread. Allows creating in
	   one thread, and using it in another. */
	void migrate_to_this_thread();
	static void init();
	static void setup_linux_system_calls(bool unsafe_syscalls = false);
	Machine(const std::vector<uint8_t>& binary, const MachineOptions&);
	Machine(std::string_view binary, const MachineOptions&);
	Machine(std::span<const uint8_t> binary, const MachineOptions&);
	Machine(const Machine& other, const MachineOptions&);
	~Machine();

private:
	void setup_registers(tinykvm_x86regs &);
	void setup_argv(__u64&, const std::vector<std::string>&, const std::vector<std::string>&);
	void setup_linux(__u64&, const std::vector<std::string>&, const std::vector<std::string>&);
	void elf_loader(std::string_view binary, const MachineOptions&);
	void elf_load_ph(std::string_view binary, const MachineOptions&, const void*);
	void dynamic_linking(std::string_view binary, const MachineOptions&);
	bool relocate_section(const char* section_name, const char* sym_section);
	void setup_long_mode(const MachineOptions&);
	void setup_cow_mode(const Machine*); // After prepare_copy_on_write and forking
	[[noreturn]] static void machine_exception(const char*, uint64_t = 0);
	[[noreturn]] static void timeout_exception(const char*, uint32_t = 0);
	void smp_vcpu_broadcast(std::function<void(vCPU&)>);

	vCPU  vcpu;
	int   fd = 0;
	bool  m_prepped = false;
	bool  m_forked = false;
	bool  m_just_reset = false;
	bool  m_relocate_fixed_mmap = false;
	bool  m_verbose_system_calls = false;
	bool  m_verbose_mmap_syscalls = false;
	bool  m_verbose_thread_syscalls = false;
	void* m_userdata = nullptr;

	std::string_view m_binary;

	vMemory memory;  // guest memory

	address_t m_image_base = 0x0;
	address_t m_stack_address;
	address_t m_heap_address;
	address_t m_brk_address;
	address_t m_brk_end_address;
	address_t m_start_address;
	address_t m_kernel_end;

	MMapCache m_mmap_cache;
	mutable std::unique_ptr<MultiThreading> m_mt;

	mutable std::unique_ptr<SMP> m_smp;
	std::unique_ptr<Signals> m_signals = nullptr;
	mutable std::unique_ptr<FileDescriptors> m_fds = nullptr;

	Machine* m_remote = nullptr;

	std::unique_ptr<MachineProfiling> m_profiling = nullptr;

	/* How to print exceptions, register dumps etc. */
	printer_func m_printer = m_default_printer;

	static std::array<syscall_t, TINYKVM_MAX_SYSCALLS> m_syscalls;
	static numbered_syscall_t m_unhandled_syscall;
	static syscall_t          m_on_breakpoint;
	static io_callback_t      m_on_input;
	static io_callback_t      m_on_output;
	static printer_func       m_default_printer;
	static mmap_func_t        m_mmap_func;

	static int create_kvm_vm();
	static int kvm_fd;
	static void* create_vcpu_timer();
	friend struct vCPU;
};

#include "machine_inline.hpp"
}
