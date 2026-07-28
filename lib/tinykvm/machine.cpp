#include "machine.hpp"

#if defined(TINYKVM_ARCH_ARM64)
#include "arm64/memory_layout.hpp"
#endif
#include "linux/threads.hpp"
#include "smp.hpp"
#include "util/scoped_profiler.hpp"
#include "util/threadpool.h"
#include <cassert>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
extern "C" int close(int);
//#define KVM_VERBOSE_MEMORY

namespace tinykvm {
	int Machine::kvm_fd = -1;
	std::array<Machine::syscall_t, TINYKVM_MAX_SYSCALLS> Machine::m_syscalls {nullptr};
	Machine::numbered_syscall_t Machine::m_unhandled_syscall = [] (vCPU&, unsigned) {};
	Machine::syscall_t Machine::m_on_breakpoint = [] (vCPU&) {};
	Machine::io_callback_t Machine::m_on_input = [] (vCPU&, unsigned, unsigned) {};
	Machine::io_callback_t Machine::m_on_output = [] (vCPU&, unsigned, unsigned) {};
	Machine::printer_func Machine::m_default_printer =
		[] (const char* buffer, size_t len) {
			printf("%.*s", (int)len, buffer);
		};
	Machine::mmap_func_t Machine::m_mmap_func = [] (vCPU&, address_t, size_t, int, int, int, address_t) {};
	static int kvm_open();
	constexpr uint64_t PageMask = vMemory::PageSize()-1;

__attribute__ ((cold))
Machine::Machine(std::string_view binary, const MachineOptions& options)
	: m_forked {false},
	  m_just_reset {false},
	  m_relocate_fixed_mmap {options.relocate_fixed_mmap},
	  memory { vMemory::New(*this, options,
	  	options.vmem_base_address, options.vmem_base_address + 0x100000, options.max_mem)
	  },
	  m_mt   {nullptr} /* Explicitly */
{
	assert(kvm_fd != -1 && "Call Machine::init() first");
	if (options.mmap_backed_files && !options.snapshot_file.empty()) {
		throw MachineException("Cannot have VM snapshot with mmap-backed files at the same time");
	}
	/* vm_group only engages for forks (like lazy_vcpu_mmap): a master owns
	   its own VM and simply passes the flag on through its fork options. */
	this->fd = create_kvm_vm();

#if defined(TINYKVM_ARCH_ARM64)
	if (memory.within(ARM64_STOP_MMIO_ADDR, vMemory::PageSize())) {
		throw MachineException("ARM64 stop MMIO address overlaps guest RAM",
			ARM64_STOP_MMIO_ADDR);
	}
	if (memory.within(ARM64_SYSCALL_MMIO_ADDR, vMemory::PageSize())) {
		throw MachineException("ARM64 syscall MMIO address overlaps guest RAM",
			ARM64_SYSCALL_MMIO_ADDR);
	}
	if (memory.within(ARM64_FATAL_MMIO_ADDR, vMemory::PageSize())) {
		throw MachineException("ARM64 fatal MMIO address overlaps guest RAM",
			ARM64_FATAL_MMIO_ADDR);
	}
#endif

	install_memory(0, memory.vmem(), false);

	this->vcpu.init(0, 0, *this, options);

	if (memory.has_loadable_snapshot_state()) {
		this->m_loaded_from_snapshot = this->load_snapshot_state();
		if (this->m_loaded_from_snapshot) {
			if (options.verbose_loader) {
				printf("Loaded VM snapshot state\n");
			}
			return;
		}
		// If the file does not exist, or anything else failed, we continue
		// to do a normal cold start.
	}

	if (!binary.empty()) {
		this->elf_loader(binary, options);
	}

	this->setup_long_mode(options);

	/* We need to adjust BRK if the kernel end address is
	   above the default BRK start address. */
	if (m_brk_address < m_kernel_end) {
		m_brk_address = m_kernel_end;
		/* We would like at least BRK_MAX bytes of space for the BRK area,
		   so we need to allocate it on the heap if it is too small. */
		if (this->m_brk_address + BRK_MAX > this->m_brk_end_address)
		{
			this->m_brk_address = mmap_allocate(BRK_MAX);
			this->m_brk_end_address = this->m_brk_address + BRK_MAX;
		}
	}

	struct tinykvm_regs regs {};
	/* Store the registers, so that Machine is ready to go */
	this->setup_registers(regs);
	this->set_registers(regs);
}
Machine::Machine(const std::vector<uint8_t>& bin, const MachineOptions& opts)
	: Machine(bin.empty() ? std::string_view{} :
		std::string_view{(const char*)bin.data(), bin.size()}, opts) {}
Machine::Machine(std::span<const uint8_t> bin, const MachineOptions& opts)
	: Machine(bin.empty() ? std::string_view{} :
		std::string_view{(const char*)bin.data(), bin.size()}, opts) {}

Machine::Machine(const Machine& other, const MachineOptions& options)
	: m_prepped {false},
	  m_forked  {true},
	  m_just_reset {true},
	  m_relocate_fixed_mmap {options.relocate_fixed_mmap},
	  m_binary {options.binary.empty() ? other.m_binary : options.binary},
	  memory   {*this, options, other.memory},
	  m_image_base    {other.m_image_base},
	  m_stack_address {other.m_stack_address},
	  m_heap_address  {other.m_heap_address},
	  m_brk_address   {other.m_brk_address},
	  m_brk_end_address {other.m_brk_end_address},
	  m_start_address {other.m_start_address},
	  m_kernel_end    {other.m_kernel_end},
	  m_mmap_cache    {other.m_mmap_cache},
	  m_mt     {nullptr}
{
	assert(kvm_fd != -1 && "Call Machine::init() first");
	if (!other.m_prepped || other.memory.main_memory_writes) {
		throw MachineException("Source Machine is not prepared for forking");
	}

	/* A seat is consumed permanently by the group if it is not handed back,
	   so any failure after acquisition must return it. */
	struct SeatGuard {
		Machine* machine = nullptr;
		~SeatGuard() {
			if (UNLIKELY(machine != nullptr))
				machine->release_group_seat();
		}
	} seat_guard;

	if (options.vm_group) {
#if defined(TINYKVM_ARCH_AMD64)
		/* Armed before acquisition: release_group_seat() is a no-op until a
		   seat is actually held, and pooled_fork_prepare() can throw after
		   taking one. */
		seat_guard.machine = this;
		this->pooled_fork_prepare(other, options);
#else
		throw MachineException("VM groups are only supported on AMD64");
#endif
	} else {
		/* Unfortunately we have to create a new VM because
		   memory is tied to VMs and not vCPUs. */
		this->fd = create_kvm_vm();

		/* Reuse pre-CoWed pagetable from the master machine */
		this->install_memory(0, memory.vmem(), false);

		/* Install mmap ranges from the master machine */
		memory.install_mmap_ranges(other);
	}

	/* Install remote VM memory too, if enabled. (read-write) */
	if (other.has_remote()) {
		this->m_remote = other.m_remote;
		this->install_memory(1, remote().memory.vmem(), false);
		// XXX: MMAP ranges are already installed above, as the
		// remote memory is shared with the main memory of the
		// master machine, so we should already have them.
		//memory.install_mmap_ranges(remote());
	}

	/* Initialize vCPU and long mode (fast path) */
#if defined(TINYKVM_ARCH_AMD64)
	if (this->is_pooled()) {
		this->vcpu.init_from_seat(*this->m_seat, *this, options);
	} else
#endif
	{
		this->vcpu.init(0, 0, *this, options);
	}
	this->setup_cow_mode(&other);

	/* We have to make a copy here, to make sure the fork knows
	   about the multi-threading state. */
	if (other.m_mt != nullptr) {
		m_mt.reset(new MultiThreading{*this});
		m_mt->reset_to(*other.m_mt);
	}
	/* Loan file descriptors from the master machine */
	if (other.m_fds != nullptr) {
		m_fds.reset(new FileDescriptors{*this});
		m_fds->reset_to(*other.m_fds);
	}

	/* Copy register state from the master machine. FPU state comes from the
	   master's prepare-time snapshot rather than a live KVM_GET_FPU: when this
	   fork is constructed from a master inherited over fork(), the master's
	   vCPU fd is not ioctl-able from this process and KVM_GET_FPU fails with
	   -EIO. See Machine::prepared_fpu_registers(). */
	auto& m_regs = other.registers();
	this->set_registers(m_regs);
	this->set_fpu_registers(other.prepared_fpu_registers());

	seat_guard.machine = nullptr;
}

#if defined(TINYKVM_ARCH_AMD64)
void Machine::pooled_fork_prepare(const Machine& other, const MachineOptions& options)
{
	/* Each of these is unfixable rather than merely unimplemented for a
	   member of a shared struct kvm, so refuse at the earliest point. */
	if (UNLIKELY(options.allow_reset_to_new_master)) {
		machine_exception("A pooled fork cannot swap the VM group's main memory");
	}
	if (UNLIKELY(other.has_remote())) {
		machine_exception("A pooled fork cannot have a remote VM");
	}
	if (UNLIKELY(options.hugepages || options.hugepages_arena_size != 0
		|| other.memory.banks.using_hugepages()))
	{
		machine_exception("A pooled fork cannot use hugepages for working memory");
	}

	auto [group, seat] = other.groups().acquire(options);
	this->m_group = std::move(group);
	this->m_seat = seat;
	/* Machine::fd keeps its meaning: it is the group's VM, shared. */
	this->fd = this->m_group->vm_fd();

	/* The group installed the master's main memory and mmap ranges once, at
	   creation: a member installs neither. VmGroupSet::acquire() treats a
	   changed range count as group *ineligibility* and opens a fresh group
	   that installs the current set, so reaching this is only possible if the
	   master grew a range concurrently with this acquisition - in which case
	   refuse, rather than hand the member a range the group's VM has no
	   memslot for and fault in the guest. */
	if (UNLIKELY(other.memory.mmap_ranges.size() != m_group->mmap_range_count())) {
		machine_exception("The master's mmap ranges changed after the VM group was created",
			other.memory.mmap_ranges.size());
	}
	memory.copy_mmap_ranges_without_install(other);

	/* Working memory is carved from this seat's partition, whose end is a
	   hard wall enforced in MemoryBanks::allocate_new_bank(). */
	memory.banks.init_from_partition(seat->arena_gpa, seat->arena_hva,
		seat->arena_size, this->m_group->max_cow_mem());
}
#endif

void Machine::release_group_seat() noexcept
{
#if defined(TINYKVM_ARCH_AMD64)
	if (this->m_group != nullptr) {
		/* NB: the debug PTE-in-partition invariant is deliberately *not* run
		   here, although a member leaving the pool is the last moment anything
		   can be said about what it did to the group. Two reasons:
		   1. It is unsafe on this path. A member may outlive its master (see
		      VmGroup::m_owner), and by then ~vMemory has munmapped the master's
		      main memory - which is where the walk starts. That is an
		      uncatchable SIGSEGV in every Debug build, in a destructor, for a
		      check that is only advisory here.
		   2. It is not where the invariant is load-bearing. reset_to() is: the
		      copy-back path resolves its write destinations through these very
		      page tables, so a violation there corrupts a sibling. A violation
		      found at release time has already happened and cannot be undone.
		   The negative tests drive the reset_to() call site. */
		vcpu.detach_to_seat(*this->m_seat);
		this->m_group->release_seat(this->m_seat, memory.banks.partition_used());
		this->m_seat = nullptr;
		/* May retire the group: VmGroupSet dropped its reference from
		   release_seat() above, so this can be the last one. */
		this->m_group = nullptr;
		this->fd = -1;
	}
#endif
}

__attribute__ ((cold))
Machine::~Machine()
{
	if (this->m_group != nullptr) {
		/* A pooled member owns neither the VM fd nor the seat's vCPU. */
		this->release_group_seat();
		return;
	}
	vcpu.deinit();
	close(this->fd);
}

void Machine::reset_to(std::string_view binary, const MachineOptions& options)
{
	ScopedProfiler<MachineProfiling::Reset> prof(this->profiling());
	if (UNLIKELY(this->is_forked() || this->is_forkable())) {
		throw MachineException("Machine is forked or forkable, cannot be reset");
	}
	/* Disconnect from the remote, if it's still connected */
	this->remote_disconnect();

	this->m_mmap_cache = {};
	this->m_mt.reset(nullptr);
	this->m_signals.reset(nullptr);
	this->m_fds.reset(nullptr);

	this->elf_loader(binary, options);

	this->vcpu.init(0, 0, *this, options);
	this->setup_long_mode(options);
	struct tinykvm_regs regs {};
	/* Store the registers, so that Machine is ready to go */
	this->setup_registers(regs);
	this->set_registers(regs);
}

bool Machine::reset_to(const Machine& other, const MachineOptions& options)
{
	ScopedProfiler<MachineProfiling::Reset> prof(this->profiling());
	assert(m_forked && other.m_prepped &&
		"This machine must be forked, and the source must be prepped");

	/* Disconnect from the remote, if it's still connected */
	this->remote_disconnect();

#ifndef NDEBUG
	/* Hazard 6, where it is load-bearing rather than a backstop: the copy-back
	   reset below (fa-serve's production recycle mode) takes the destination of
	   every restored page from this member's own page tables, so it writes
	   inside this member's partition if and only if the page tables are inside
	   it. Prove that before the loop, not after. A no-op unless pooled. */
	this->assert_pte_partition_invariant();
#endif

	bool full_reset = false;
	if (UNLIKELY(this->m_binary.begin() != other.m_binary.begin() ||
		memory.compare(other.memory) == false))
	{
		if (options.allow_reset_to_new_master == false) {
			throw MachineException("Swapping main memories not enabled (experimental)");
		}
		if (UNLIKELY(this->is_pooled())) {
			/* Not scopeable: slot 0 is the VM group's, shared with every
			   sibling, and a member cannot swap it out from under them. */
			machine_exception("A pooled VM group member cannot be reset to a new master");
		}
		if (options.reset_keep_all_work_memory) {
			throw MachineException("Cannot reset to new Machine with old work memory");
		}

		/* This could be dangerous, but we will allow it anyway,
		   for those who dare to mutate an existing VM in prod. */
		this->m_binary = other.m_binary;
		this->m_image_base    = other.m_image_base;
		this->m_stack_address = other.m_stack_address;
		this->m_heap_address  = other.m_heap_address;
		this->m_brk_address   = other.m_brk_address;
		this->m_brk_end_address = other.m_brk_end_address;
		this->m_start_address = other.m_start_address;
		this->m_kernel_end    = other.m_kernel_end;
		memory.fork_reset(other.memory, options);
		/* Unfortunately we need to both delete and reinstall main mem */
		this->delete_memory(0);
		this->install_memory(0, memory.vmem(), true);
		/* Swap remote memory, when enabled. */
		if (this->has_remote()) {
			this->delete_memory(1);
			this->install_memory(1, remote().memory.vmem(), true);
		}
		full_reset = true;
	} else {
		full_reset = memory.fork_reset(other, options);
	}

	this->m_just_reset = full_reset;
	this->m_mmap_cache = other.m_mmap_cache;
	this->vcpu.last_fault_address = 0;

	if (other.has_threads() && has_threads()) {
		this->m_mt->reset_to(*other.m_mt);
	} else if (other.has_threads()) {
		this->m_mt.reset(new MultiThreading{*this});
		this->m_mt->reset_to(*other.m_mt);
	} else {
		m_mt = nullptr;
	}
	/* Reset the file descriptors */
	this->fds().reset_to(other.fds());

	/* Drop any TLB-invalidation signal left over from the previous turn so a
	   stale page address can't be delivered to the next turn's syscall stub. */
	this->m_pending_tlb_signal = 0;

	if (full_reset) {
		this->setup_cow_mode(&other);
	}
#if defined(TINYKVM_ARCH_AMD64)
	else {
		/* Copy-back reset keeps the fork's page tables and skips
		   setup_cow_mode(), so the guest's segment/mode state (CS/SS, CR0)
		   is whatever the fork was stopped in. A fork interrupted
		   mid-execution in user mode (e.g. a watchdog timeout while the
		   guest was spinning) would otherwise resume the master's parked
		   kernel-mode trampoline (a sysret) in user mode and #PF on the
		   kernel page. Restore the master's special registers, keeping the
		   fork's own page tables (CR3). */
		struct kvm_sregs sregs = other.get_special_registers();
		sregs.cr3 = this->memory.page_tables;
		this->vcpu.set_special_registers(sregs);
	}
#endif

	if (options.reset_copy_all_registers) {
		/* Copy register state from the master machine (FPU from the master's
		   prepare-time snapshot; see the fork constructor). */
		auto& m_regs = other.registers();
		this->set_registers(m_regs);
		this->set_fpu_registers(other.prepared_fpu_registers());
	}
	if (options.reset_enter_usermode) {
		/* Enforce usermode (default). This will crash guests
		   that were handling a system call during fork. */
		this->enter_usermode();
	}
	return full_reset;
}

uint64_t Machine::stack_push(__u64& sp, const void* data, size_t length)
{
	sp = (sp - length) & ~(uint64_t) 0x7; // maintain word alignment
	copy_to_guest(sp, data, length, true);
	return sp;
}
uint64_t Machine::stack_push_cstr(__u64& sp, const char* string)
{
	return stack_push(sp, string, strlen(string)+1);
}
uint64_t Machine::stack_push_cstr(__u64& sp, const char* string, size_t length)
{
	const size_t buffer_length = length + 1;
	sp = (sp - buffer_length) & ~(uint64_t) 0x7; // maintain word alignment
	if (string[length] == 0) {
		copy_to_guest(sp, string, length + 1, true);
	} else {
		// Fallback: copy the string and zero out the last byte
		copy_to_guest(sp, string, length, true);
		// Zero out the last byte
		uint8_t zero = 0;
		copy_to_guest(sp + length, &zero, sizeof(zero), true);
	}
	return sp;
}

void Machine::install_memory(uint32_t idx, const VirtualMem& mem,
	[[maybe_unused]] bool readonly)
{
	/* A pooled member owns no memslots: every one of this VM's slots belongs to
	   the group and is shared with every sibling. The slot index would come from
	   this member's own MemoryBanks allocator, which starts at FIRST_BANK_IDX -
	   i.e. it would land on the group's first mmap-range slot, or on its arena
	   slot, and replace a region every sibling is running out of. Nothing in the
	   tree reaches this today (the group installs main memory and the mmap
	   ranges itself, partitioned banks are carved rather than installed, and the
	   remaining callers are refused earlier or are masters), so this closes a
	   class rather than a live bug - and makes "a live group performs no memslot
	   operations" executable instead of conventional. */
	if (UNLIKELY(this->is_pooled())) {
		machine_exception("A pooled VM group member cannot install a memory region", idx);
	}
	VmGroup::note_memslot_op();
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = readonly ? (uint32_t)KVM_MEM_READONLY : 0u,
		.guest_phys_addr = mem.physbase,
		.memory_size = mem.size,
		.userspace_addr = (uintptr_t) mem.ptr,
	};
#ifdef KVM_VERBOSE_MEMORY
	printf("UMR: Install slot %u with flags 0x%X at 0x%llX to 0x%llX (%zu bytes) from %p\n",
		memreg.slot, memreg.flags, memreg.guest_phys_addr,
		memreg.guest_phys_addr + mem.size, mem.size, mem.ptr);
#endif
	if (UNLIKELY(ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0)) {
		throw MemoryException("Failed to install guest memory region", mem.physbase, mem.size);
	}
}
void Machine::delete_memory(uint32_t idx)
{
	/* Worse than installing one, and refused for the same reason: deleting a
	   slot of the group's VM removes memory from every sibling at once, with
	   slots_lock held and an expedited SRCU sync, on a VM whose other members
	   may be inside KVM_RUN. Under PerGroup arena slots the slot in question is
	   the whole arena. */
	if (UNLIKELY(this->is_pooled())) {
		machine_exception("A pooled VM group member cannot delete a memory region", idx);
	}
	VmGroup::note_memslot_op();
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = 0u,
		.guest_phys_addr = 0x0,
		.memory_size = 0x0,
		.userspace_addr = 0x0,
	};
#ifdef KVM_VERBOSE_MEMORY
	printf("UMR: Remove slot %u\n", memreg.slot);
#endif
	if (UNLIKELY(ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0)) {
		machine_exception("Failed to delete guest memory region", idx);
	}
}
uint64_t Machine::translate(uint64_t virt) const
{
	struct kvm_translation tr;
	tr.linear_address = virt;
	if (ioctl(vcpu.fd, KVM_TRANSLATE, &tr) < 0) {
		return 0x0;
	}
	//printf("Translated 0x%lX to 0x%lX\n", virt, tr.physical_address);
	return tr.physical_address;
}

void Machine::setup_registers(tinykvm_regs& regs)
{
#if defined(TINYKVM_ARCH_AMD64)
	/* Set IOPL=3 to allow I/O instructions, IF *NOT* enabled */
	regs.rflags = 2 | (3 << 12); // IF: 0x200
	regs.rip = this->start_address();
	regs.rsp = this->stack_address();
#elif defined(TINYKVM_ARCH_ARM64)
	regs.pc = this->start_address();
	regs.sp = this->stack_address();
	/* EL0t with DAIF masked: guests run in usermode. */
	regs.pstate = 0x3c0;
#endif
}

long Machine::return_value() const
{
#if defined(TINYKVM_ARCH_AMD64)
	return registers().rdi;
#elif defined(TINYKVM_ARCH_ARM64)
	return registers().regs[0];
#endif
}

void Machine::print(const char* buffer, size_t len)
{
	m_printer(buffer, len);
}

void Machine::run(float timeout)
{
	return vcpu.run(timeout * 1000.0);
}

void Machine::run_in_usermode(float timeout)
{
	this->enter_usermode();
	this->run(timeout);
}

__attribute__((cold, noreturn))
void Machine::machine_exception(const char* msg, uint64_t data)
{
	throw MachineException(msg, data);
}

__attribute__((cold, noreturn))
void Machine::timeout_exception(const char* msg, uint32_t data)
{
	throw MachineTimeoutException(msg, data);
}

__attribute__ ((cold))
int kvm_open()
{
	int fd = open("/dev/kvm", O_RDWR);
	if (fd < 0) {
		throw MachineException("Failed to open /dev/kvm");
	}

	const int api_ver = ioctl(fd, KVM_GET_API_VERSION, 0);
	if (api_ver < 0) {
		throw MachineException("Failed to verify KVM_GET_API_VERSION");
	}

	if (api_ver != KVM_API_VERSION) {
		fprintf(stderr, "Got KVM api version %d, expected %d\n",
			api_ver, KVM_API_VERSION);
		throw MachineException("Wrong KVM API version");
	}

	/* Host limits that bound a VM group: the vCPU count wall in particular. */
	KvmLimits::query(fd);

	extern void initialize_vcpu_stuff(int kvm_fd);
	initialize_vcpu_stuff(fd);

	/* Setup the default syscall table */
	Machine::setup_linux_system_calls();

	return fd;
}

__attribute__ ((cold))
void Machine::init()
{
	Machine::kvm_fd = kvm_open();
}

__attribute__ ((cold))
int Machine::create_kvm_vm()
{
#if defined(TINYKVM_ARCH_ARM64)
	const int ipa_size = ioctl(kvm_fd, KVM_CHECK_EXTENSION, KVM_CAP_ARM_VM_IPA_SIZE);
	const unsigned long vm_type = ipa_size > 0 ? KVM_VM_TYPE_ARM_IPA_SIZE(ipa_size) : 0;
#else
	const unsigned long vm_type = 0;
#endif
	int fd = ioctl(kvm_fd, KVM_CREATE_VM, vm_type);
	if (UNLIKELY(fd < 0)) {
		machine_exception("Failed to KVM_CREATE_VM", errno);
	}

	/*if (ioctl(fd, KVM_SET_TSS_ADDR, 0xffffd000) < 0) {
		throw MachineException("Failed to KVM_SET_TSS_ADDR");
	}*/

	/*__u64 map_addr = 0xffffc000;
	if (ioctl(fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr) < 0) {
		throw MachineException("Failed KVM_SET_IDENTITY_MAP_ADDR");
	}*/

	return fd;
}

}
