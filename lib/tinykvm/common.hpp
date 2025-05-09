#pragma once

#ifndef LIKELY
#define LIKELY(x) __builtin_expect((x), 1)
#endif
#ifndef UNLIKELY
#define UNLIKELY(x) __builtin_expect((x), 0)
#endif

#ifndef TINYKVM_MAX_SYSCALLS
#define TINYKVM_MAX_SYSCALLS  512
#endif

#define TINYKVM_COLD()   __attribute__ ((cold))

#include <cstdint>
#include <exception>
#include <string>
#include <string_view>
#include <vector>

namespace tinykvm
{
	struct VirtualRemapping {
		uint64_t phys;
		uint64_t virt;
		size_t   size;
		bool     writable = false;
		bool     executable = false;
		bool     blackout = false; /* Unmapped virtual area */
	};

	struct MachineOptions {
		uint64_t max_mem = 16ULL << 20; /* 16MB */
		uint32_t max_cow_mem = 0;
		uint32_t stack_size = 1600UL << 10; /* 1600KB */
		uint32_t reset_free_work_mem = 0; /* reset_to() */
		uint32_t dylink_address_hint = 0x200000; /* 2MB */
		uint32_t heap_address_hint = 0;
		uint64_t vmem_base_address = 0;
		std::string_view binary = {};
		std::vector<VirtualRemapping> remappings {};

		bool verbose_loader = false;
		bool short_lived = false;
		bool hugepages = false;
		bool transparent_hugepages = false;
		/* When enabled, master VMs will write directly
		   to their own main memory instead of memory banks,
		   allowing forks to immediately see changes. */
		bool master_direct_memory_writes = false;
		/* When enabled, split hugepages during page faults. */
		bool split_hugepages = false;
		/* When enabled, reset_to() will accept a different
		   master VM than the original, but at a steep cost. */
		bool allow_reset_to_new_master = false;
		/* When enabled, reset_to() will copy all registers
		   from the master VM to the new VM. */
		bool reset_copy_all_registers = true;
		/* When enabled, reset_to() will copy all memory
		   from the master VM to the forked VM instead of
		   resetting the memory banks. */
		bool reset_keep_all_work_memory = false;
		/* Force-relocate fixed addresses with mmap(). */
		bool relocate_fixed_mmap = true;
		/* Make heap executable, to support JIT. */
		bool executable_heap = false;
		/* When enabled, the VM will use rdtsc for all clocks
		   except CLOCK_REALTIME. */
		bool clock_gettime_uses_rdtsc = false;
		/* When using hugepages, cover the given size with
		   hugepages, unless 0, in which case the entire
		   main memory will be covered. */
		size_t hugepages_arena_size = 0UL;
	};

	class MachineException : public std::exception {
	public:
	    MachineException(const char* msg, uint64_t data = 0)
			: m_msg(msg), m_data(data) {}
	    const char* what() const noexcept override {
	        return m_msg;
	    }
		auto data() const noexcept { return m_data; }
	protected:
		const char* m_msg;
		uint64_t m_data;
	};

	class MachineTimeoutException: public MachineException {
	public:
		using MachineException::MachineException;
		float seconds() const noexcept { return data() / 1000.0; }
	};

	class MemoryException: public MachineException {
	public:
	    MemoryException(const char* msg, uint64_t addr, uint64_t sz)
			: MachineException{msg, addr}, m_size(sz) {}
	    const char* what() const noexcept override {
	        return m_msg;
	    }
		auto addr() const noexcept { return data(); }
		auto size() const noexcept { return m_size; }
	private:
		uint64_t m_size;
	};

	template <class...> constexpr std::false_type always_false {};

	template<typename T>
	struct is_string
		: public std::disjunction<
			std::is_same<char *, typename std::decay<T>::type>,
			std::is_same<const char *, typename std::decay<T>::type>
	> {};

	template<class T>
	struct is_stdstring : public std::is_same<T, std::basic_string<char>> {};

	struct PerVCPUTable {
		int cpuid;
		int userval1;
		int userval2;
		int userval3;
	};

	struct DynamicElf {
		std::string interpreter;
		bool is_dynamic;

		bool has_interpreter() const noexcept {
			return !interpreter.empty();
		}
	};
	extern DynamicElf is_dynamic_elf(std::string_view bin);
}
