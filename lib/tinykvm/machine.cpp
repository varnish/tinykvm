#include "machine.hpp"

#include "threads.hpp"
#include "smp.hpp"
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
	static int kvm_open();
	constexpr uint64_t PageMask = vMemory::PageSize()-1;

__attribute__ ((cold))
Machine::Machine(std::string_view binary, const MachineOptions& options)
	: m_forked {false},
	  m_just_reset {false},
	  m_allow_fixed_mmap {options.allow_fixed_mmap},
	  memory { vMemory::New(*this, options,
	  	options.vmem_base_address, options.vmem_base_address + 0x100000, options.max_mem)
	  },
	  m_mt   {nullptr} /* Explicitly */
{
	assert(kvm_fd != -1 && "Call Machine::init() first");

	this->fd = create_kvm_vm();

	install_memory(0, memory.vmem(), false);

	if (!binary.empty()) {
		this->elf_loader(binary, options);
	}

	this->vcpu.init(0, *this);
	this->setup_long_mode(options);
	struct tinykvm_regs regs {};
	/* Store the registers, so that Machine is ready to go */
	this->setup_registers(regs);
	this->set_registers(regs);
}
Machine::Machine(const std::vector<uint8_t>& bin, const MachineOptions& opts)
	: Machine(std::string_view{(const char*)&bin[0], bin.size()}, opts) {}

Machine::Machine(const Machine& other, const MachineOptions& options)
	: m_prepped {false},
	  m_forked  {true},
	  m_just_reset {true},
	  m_allow_fixed_mmap {options.allow_fixed_mmap},
	  m_binary {options.binary.empty() ? other.m_binary : options.binary},
	  memory   {*this, options, other.memory},
	  m_image_base    {other.m_image_base},
	  m_stack_address {other.m_stack_address},
	  m_heap_address  {other.m_heap_address},
	  m_start_address {other.m_start_address},
	  m_kernel_end    {other.m_kernel_end},
	  m_mm            {other.m_mm},
	  m_mmap_cache    {other.m_mmap_cache},
	  m_mt     {nullptr}
{
	assert(kvm_fd != -1 && "Call Machine::init() first");
	assert(other.m_prepped && "Call Machine::prepare_copy_on_write() first");

	/* Unfortunately we have to create a new VM because
	   memory is tied to VMs and not vCPUs. */
	this->fd = create_kvm_vm();

	/* Reuse pre-CoWed pagetable from the master machine */
	this->install_memory(0, memory.vmem(), true);

	/* Install remote VM memory too, if enabled. (read-write) */
	if (other.is_remote_connected()) {
		this->m_remote = other.m_remote;
		this->install_memory(1, remote().memory.vmem(), false);
	}

	/* Initialize vCPU and long mode (fast path) */
	this->vcpu.init(0, *this);
	this->setup_cow_mode(&other);

	/* We have to make a copy here, to make sure the fork knows
	   about the multi-threading state. */
	if (other.m_mt != nullptr) {
		m_mt.reset(new MultiThreading{*this});
		m_mt->reset_to(*other.m_mt);
	}
}

__attribute__ ((cold))
Machine::~Machine()
{
	vcpu.deinit();
	close(this->fd);
}

void Machine::reset_to(std::string_view binary, const MachineOptions& options)
{
	if (UNLIKELY(this->is_forked() || this->is_forkable())) {
		throw MachineException("Machine is forked or forkable, cannot be reset");
	}
	this->m_mmap_cache = {};
	this->m_mt.reset(nullptr);
	this->m_signals.reset(nullptr);

	this->elf_loader(binary, options);

	this->vcpu.init(0, *this);
	this->setup_long_mode(options);
	struct tinykvm_regs regs {};
	/* Store the registers, so that Machine is ready to go */
	this->setup_registers(regs);
	this->set_registers(regs);
}

void Machine::reset_to(const Machine& other, const MachineOptions& options)
{
	assert(m_forked && other.m_prepped &&
		"This machine must be forked, and the source must be prepped");

	if (UNLIKELY(this->m_binary.begin() != other.m_binary.begin() ||
		memory.compare(other.memory) == false))
	{
		if (options.allow_reset_to_new_master == false) {
			throw MachineException("Swapping main memories not enabled (experimental)");
		}

		/* This could be dangerous, but we will allow it anyway,
		   for those who dare to mutate an existing VM in prod. */
		this->m_binary = other.m_binary;
		this->m_image_base    = other.m_image_base;
		this->m_stack_address = other.m_stack_address;
		this->m_heap_address  = other.m_heap_address;
		this->m_start_address = other.m_start_address;
		this->m_kernel_end    = other.m_kernel_end;
		memory.fork_reset(other.memory, options);
		/* Unfortunately we need to both delete and reinstall main mem */
		this->delete_memory(0);
		this->install_memory(0, memory.vmem(), true);
		/* Swap remote memory, when enabled. */
		if (this->is_remote_connected()) {
			this->delete_memory(1);
			this->install_memory(1, remote().memory.vmem(), true);
		}
	} else {
		memory.fork_reset(options);
	}

	this->m_just_reset = true;
	this->m_mm = other.m_mm;
	this->m_mmap_cache = other.m_mmap_cache;

	if (other.has_threads() && has_threads()) {
		this->m_mt->reset_to(*other.m_mt);
	} else if (other.has_threads()) {
		this->m_mt.reset(new MultiThreading{*this});
		this->m_mt->reset_to(*other.m_mt);
	} else {
		m_mt = nullptr;
	}

	this->setup_cow_mode(&other);
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

void Machine::install_memory(uint32_t idx, const VirtualMem& mem,
	[[maybe_unused]] bool readonly)
{
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = 0u, //(ro) ? (uint32_t)KVM_MEM_READONLY : 0u,
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

/* TODO: Serialize access with mutex. */
Machine::address_t Machine::mmap_allocate(size_t bytes)
{
	address_t result = this->m_mm;
	/* Bytes rounded up to nearest 4k (PAGE_SIZE). */
	this->m_mm += (bytes + PageMask) & ~PageMask;
	return result;
}
bool Machine::mmap_unmap(uint64_t addr, size_t size)
{
	const bool relaxed = this->mmap_relax(addr, size, 0u);
	if (relaxed)
	{
		// If relaxation happened, invalidate intersecting cache entries.
		this->mmap_cache().invalidate(addr, size);
	}
	else if (addr >= this->mmap_start())
	{
		// If relaxation didn't happen, put in the cache for later.
		this->mmap_cache().insert(addr, size);
	}
	return relaxed;
}
bool Machine::mmap_relax(uint64_t addr, size_t size, size_t new_size)
{
	if (this->m_mm == addr + size && new_size <= size) {
		this->m_mm = (addr + new_size + PageMask) & ~PageMask;
		return true;
	}
	return false;
}

void Machine::print(const char* buffer, size_t len)
{
	m_printer(buffer, len);
}

void Machine::run(float timeout)
{
	return vcpu.run(timeout * 1000.0);
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
