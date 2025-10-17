#include "machine.hpp"

#include "linux/threads.hpp"
#include "smp.hpp"
#include "util/scoped_profiler.hpp"
#include "util/threadpool.h"
#include <cassert>
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

	this->fd = create_kvm_vm();

	install_memory(0, memory.vmem(), false);

	this->vcpu.init(0, *this, options);

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
	: Machine(std::string_view{(const char*)&bin[0], bin.size()}, opts) {}
Machine::Machine(std::span<const uint8_t> bin, const MachineOptions& opts)
	: Machine(std::string_view{(const char*)bin.data(), bin.size()}, opts) {}

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

	/* Unfortunately we have to create a new VM because
	   memory is tied to VMs and not vCPUs. */
	this->fd = create_kvm_vm();

	/* Reuse pre-CoWed pagetable from the master machine */
	this->install_memory(0, memory.vmem(), false);

	/* Install mmap ranges from the master machine */
	memory.install_mmap_ranges(other);

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
	this->vcpu.init(0, *this, options);
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

	/* Copy register state from the master machine */
	auto& m_regs = other.registers();
	this->set_registers(m_regs);
	this->set_fpu_registers(other.fpu_registers());
}

__attribute__ ((cold))
Machine::~Machine()
{
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

	this->vcpu.init(0, *this, options);
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

	bool full_reset = false;
	if (UNLIKELY(this->m_binary.begin() != other.m_binary.begin() ||
		memory.compare(other.memory) == false))
	{
		if (options.allow_reset_to_new_master == false) {
			throw MachineException("Swapping main memories not enabled (experimental)");
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

	if (full_reset) {
		this->setup_cow_mode(&other);
	}

	if (options.reset_copy_all_registers) {
		/* Copy register state from the master machine */
		auto& m_regs = other.registers();
		this->set_registers(m_regs);
		this->set_fpu_registers(other.fpu_registers());
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
	/* Set IOPL=3 to allow I/O instructions, IF *NOT* enabled */
	regs.rflags = 2 | (3 << 12); // IF: 0x200
	regs.rip = this->start_address();
	regs.rsp = this->stack_address();
}

long Machine::return_value() const
{
	return registers().rdi;
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
	int fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (UNLIKELY(fd < 0)) {
		machine_exception("Failed to KVM_CREATE_VM. Is your user in the 'kvm' group?");
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
