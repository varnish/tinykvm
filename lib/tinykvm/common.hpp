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

#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static constexpr inline uint64_t PageMask() {
	return PAGE_SIZE - 1UL;
}

/* Default for MachineOptions::lazy_vcpu_mmap. Build with
   -DTINYKVM_LAZY_VCPU_MMAP_DEFAULT=true to make every fork lazy,
   which is how the unit test suite is A/B'ed against the eager path. */
#ifndef TINYKVM_LAZY_VCPU_MMAP_DEFAULT
#define TINYKVM_LAZY_VCPU_MMAP_DEFAULT false
#endif

/* Default for MachineOptions::vm_group. Build with
   -DTINYKVM_VM_GROUP_DEFAULT=true to pool every fork, which is how the
   unit test suite is A/B'ed against the one-VM-per-fork path. */
#ifndef TINYKVM_VM_GROUP_DEFAULT
#define TINYKVM_VM_GROUP_DEFAULT false
#endif

#include <array>
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

	/* How a VM group protects the *host* address space against a linear
	   overrun off the end of a seat's arena partition. The guest-physical side
	   of the guard band is free and always on (a seat's memslot stops at
	   arena_size, so the band has no backing in the group's VM at all); this
	   is only about what the host sees when C++ code - page_duplicate(), a
	   memcpy() walking past the last bank - runs off the end.
	   Auto resolves once, at group construction:
	     Madvise if the kernel supports MADV_GUARD_INSTALL, else
	     Mprotect in debug builds, else Off.
	   Costs:
	     Mprotect: 2 VMAs and 2 mmap_lock write acquisitions per seat (the
	       group window is reserved PROT_NONE and each seat mprotect()s its
	       usable part RW), which is the layout tinykvm shipped before the
	       group window existed. Every VMA is walked and locked by every later
	       KVM_CREATE_VM (mm_take_all_locks), so this is the expensive mode.
	     Madvise: 0 VMAs - MADV_GUARD_INSTALL marks PTEs, it does not split the
	       mapping - but needs kernel >= 6.13.
	     Off: 0 VMAs and no probe. Host-side overrun protection then falls to
	       the allocator wall in MemoryBanks::allocate_new_bank() (which
	       refuses a bank past the partition end before deriving its HVA), the
	       GPA-side guard, and, in debug builds, the PTE-partition invariant. */
	enum class VmGroupHostGuard : uint8_t {
		Auto = 0,
		Off,
		Madvise,
		Mprotect,
	};

	struct MachineProfiling {
		enum Location {
			VCpuRun = 0,
			Reset = 1,
			Syscall = 2,
			PageFault = 3,
			MMapFiles = 4,
			RemoteResume = 5,
			UserDefined = 6,
			Count = 7
		};
		// Each entry contains a list of times in nanoseconds
		std::array<std::vector<uint64_t>, Count> times;
		// Print profiling results. Side effect: *sorts vectors*
		// when user_defined is non-empty, it will use that label
		// instead of "UserDefined"
		void print(const char* user_defined = "") const;
		// Clear all profiling samples
		void reset() {
			for (auto& vec : times)
				vec.clear();
		}
		void clear() { reset(); } // Alias
	};

	struct MachineOptions {
		uint64_t max_mem = 16ULL << 20; /* 16MB */
		uint32_t max_cow_mem = 0;
		uint32_t stack_size = 1600UL << 10; /* 1600KB */
		uint32_t reset_free_work_mem = 0; /* reset_to() */
		uint64_t dylink_address_hint = 0x200000; /* 2MB */
		uint64_t heap_address_hint = 0;
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
		/* When enabled, split hugepages during page faults. This will also
		   split hugepages during ELF loading for 2MB-aligned entries. */
		bool split_hugepages = false;
		/* When enabled, split all hugepages during ELF loading making the entire
		   guest memory area consist of 4k leaf pages only. This consumes more
		   memory and requires extra page-walking, but makes copy-on-write handling
		   simpler and will make the ACCESS bit more granular. */
		bool split_all_hugepages_during_loading = false;
		/* When enabled, reset_to() will accept a different
		   master VM than the original, but at a steep cost. */
		bool allow_reset_to_new_master = false;
		/* When enabled, reset_to() will copy all registers
		   from the master VM to the new VM. */
		bool reset_copy_all_registers = true;
		/* When reset_enter_usermode is enabled, the guest will
		   be forced into usermode after reset_to(). */
		bool reset_enter_usermode = true;
		/* When enabled, reset_to() will copy all memory
		   from the master VM to the forked VM instead of
		   resetting the memory banks. */
		bool reset_keep_all_work_memory = false;
		/* Force-relocate fixed addresses with mmap(). */
		bool relocate_fixed_mmap = true;
		/* Make heap executable, to support JIT. */
		bool executable_heap = false;
		/* Enable file-backed memory mappings for large files */
		bool mmap_backed_files = false;
		/* When enabled, a forked VM does not mmap its vCPUs kvm_run page
		   during construction, but on its first run. Each mapping is a
		   VMA that every later KVM_CREATE_VM has to walk and lock, so
		   parked forks that never run become much cheaper to create.
		   Until the first run the registers live in a userspace shadow.
		   Only forks are affected: a master VM is always mapped eagerly,
		   as its registers are read through the mapping by forks
		   constructed in a process that inherited it over fork().
		   (AMD64 only.) */
		bool lazy_vcpu_mmap = TINYKVM_LAZY_VCPU_MMAP_DEFAULT;
		/* Pool this fork into a shared struct kvm with up to vm_group_size
		   siblings of the same master, instead of creating a VM of its own.
		   Removes the per-fork KVM_CREATE_VM, and with it both the
		   mm_take_all_locks VMA walk and the host-global PM-notifier chain
		   walk. Forks only, and refused for machines that enable
		   allow_reset_to_new_master, a remote VM, SMP or hugepages.
		   (AMD64 only.) */
		bool vm_group = TINYKVM_VM_GROUP_DEFAULT;
		/* Members per group (B). 0 = let VmGroup pick, bounded by
		   KVM_CAP_MAX_VCPUS. */
		uint32_t vm_group_size = 0;
		/* Host-side guard band mode for this group's arena. See
		   VmGroupHostGuard above. Resolved and frozen at group construction:
		   the group's arena window is *mapped* according to it, so it cannot be
		   retrofitted onto a group that already exists. It is therefore part of
		   group eligibility, exactly like max_cow_mem is - Auto joins any
		   existing group (it means "whatever this host can give", which such a
		   group has already decided), while an explicit Off/Madvise/Mprotect
		   only joins a group that resolved to that same mode and otherwise
		   opens a new one. In practice a process picks once at startup, so the
		   set never bifurcates. An explicit Madvise on a kernel without
		   MADV_GUARD_INSTALL is an error rather than a silent downgrade. */
		VmGroupHostGuard vm_group_host_guard = VmGroupHostGuard::Auto;
		/* Enable VM snapshot by file-mapping all physical memory
		   to the given file. Depending on `snapshot_mode`,
		   the file may be created if it does not exist,
		   and must be of the correct size if it does exist. */
		std::string snapshot_file {};
		enum SnapshotMode {
			Disabled = 0,
			Open = 1,
			Create = 2,
			OpenOrCreate = 3,
		};
		/* When using a snapshot_file, control whether file
		   should be created if missing, opened, or created
		   and possibly overwritten. */
		SnapshotMode snapshot_mode = OpenOrCreate;
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
	    MemoryException(const char* msg, uint64_t addr, uint64_t sz, bool oom = false)
			: MachineException{msg, addr}, m_size(sz), m_is_oom(oom) {}
	    const char* what() const noexcept override {
	        return m_msg;
	    }
		auto addr() const noexcept { return data(); }
		auto size() const noexcept { return m_size; }
		bool is_oom() const noexcept { return m_is_oom; }
	private:
		uint64_t m_size;
		bool m_is_oom = false; /* True if the exception was caused by OOM */
	};

	class RetryException: public MachineException {
	public:
		RetryException() : MachineException("Retry", 0) {}
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
