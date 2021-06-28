#include "machine.hpp"

#include "kernel/amd64.hpp"
#include "kernel/vdso.hpp"
#include <cassert>
#include <cstring>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include <stdexcept>
#include "void_async.hpp"

namespace tinykvm {
	int Machine::kvm_fd = -1;
	std::array<Machine::syscall_t, TINYKVM_MAX_SYSCALLS> Machine::m_syscalls {nullptr};
	Machine::unhandled_syscall_t Machine::m_unhandled_syscall = [] (Machine&, unsigned) {};
	static int kvm_open();
	long vcpu_mmap_size = 0;

Machine::Machine(std::string_view binary, const MachineOptions& options)
	: m_binary {binary}
{
	assert(kvm_fd != -1 && "Call Machine::init() first");

	/* Automatically enable threads when SYS_clone is installed */
	if (get_syscall_handler(56) != nullptr) {
		m_mt.reset(new MultiThreading{*this});
	}

	this->fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (UNLIKELY(this->fd < 0)) {
		throw std::runtime_error("Failed to KVM_CREATE_VM");
	}

	if (ioctl(this->fd, KVM_SET_TSS_ADDR, 0xffffd000) < 0) {
		throw std::runtime_error("Failed to KVM_SET_TSS_ADDR");
	}

	__u64 map_addr = 0xffffc000;
	if (ioctl(this->fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr) < 0) {
		throw std::runtime_error("Failed KVM_SET_IDENTITY_MAP_ADDR");
	}

	this->mmio_scall = MemRange::New("System calls", 0xffffa000, 0x1000);

	/* Disallow viewing memory below 1MB */
	this->memory = vMemory::New(0x0, 0x100000, options.max_mem);
	if (UNLIKELY(install_memory(0, this->memory) < 0)) {
		throw std::runtime_error("Failed to install guest memory region");
	}

	/* vsyscall page */
	this->vsyscall = vMemory::From(0xFFFF600000, (char*) vdso_page().data(), vdso_page().size());
	if (UNLIKELY(install_memory(1, this->vsyscall) < 0)) {
		throw std::runtime_error("Failed to install guest memory region");
	}

	this->elf_loader(options);

	this->vcpu.init(*this);
	this->setup_long_mode(nullptr);
	struct tinykvm_x86regs regs {0};
	/* Store the registers, so that Machine is ready to go */
	this->setup_registers(regs);
	this->set_registers(regs);
}
Machine::Machine(const std::vector<uint8_t>& bin, const MachineOptions& opts)
	: Machine(std::string_view{(const char*)&bin[0], bin.size()}, opts) {}

Machine::Machine(const Machine& other, const MachineOptions& options)
	: m_binary {other.m_binary},
	  m_stopped {true},
	  m_exit_address {other.m_exit_address},
	  m_stack_address {other.m_stack_address},
	  m_heap_address {other.m_heap_address},
	  m_start_address {other.m_start_address},
	  ptmem    {other.ptmem},
	  m_mm     {other.m_mm},
	  m_mt     {new MultiThreading{*other.m_mt}}
{
	assert(kvm_fd != -1 && "Call Machine::init() first");

	this->fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (UNLIKELY(this->fd < 0)) {
		throw std::runtime_error("Failed to KVM_CREATE_VM");
	}

	/* Reuse pre-CoWed pagetable from the master machine */
	this->memory = vMemory::From(other.memory, m_banks);

	if (UNLIKELY(install_memory(0, this->memory) < 0)) {
		throw std::runtime_error("Failed to install guest memory region");
	}

	/* MMIO syscall page */
	this->mmio_scall = MemRange::New("System calls", 0xffffa000, 0x1000);

	/* vsyscall page */
	this->vsyscall = vMemory::From(0xFFFF600000, (char*) vdso_page().data(), vdso_page().size());
	if (UNLIKELY(install_memory(1, other.vsyscall) < 0)) {
		throw std::runtime_error("Failed to install guest memory region");
	}

	this->vcpu.init(*this);

	this->setup_long_mode(&other);

	this->set_registers(other.registers());
}

void Machine::init()
{
	Machine::kvm_fd = kvm_open();
}

uint64_t Machine::stack_push(__u64& sp, const void* data, size_t length)
{
	sp = (sp - length) & ~0x7; // maintain word alignment
	// TODO: fault-in new page
	
	std::memcpy(memory.safely_at(sp, length), data, length);

	return sp;
}

int Machine::install_memory(uint32_t idx, vMemory mem)
{
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = (mem.ptr) ? 0u : (uint32_t) KVM_MEM_READONLY,
		.guest_phys_addr = mem.physbase,
		.memory_size = mem.size,
		.userspace_addr = (uintptr_t) mem.ptr,
	};
	return ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg);
}
int Machine::delete_memory(uint32_t idx)
{
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = 0u,
		.guest_phys_addr = 0x0,
		.memory_size = 0x0,
		.userspace_addr = 0x0,
	};
	return ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg);
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

void Machine::setup_registers(tinykvm_x86regs& regs)
{
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.rip = this->start_address();
	regs.rsp = this->stack_address();
}

void Machine::reset()
{
	//m_mt.reset(new MultiThreading{*this});
	//memory.reset();
}

Machine::~Machine()
{
	if (fd > 0) {
		close(fd);
	}
	vcpu.deinit();
	if (memory.owned) {
		munmap(memory.ptr, memory.size);
	}
}

__attribute__ ((cold))
int kvm_open()
{
	int fd = open("/dev/kvm", O_RDWR);
	if (fd < 0) {
		throw std::runtime_error("Failed to open /dev/kvm");
	}

	const int api_ver = ioctl(fd, KVM_GET_API_VERSION, 0);
	if (api_ver < 0) {
		throw std::runtime_error("Failed to verify KVM_GET_API_VERSION");
	}

	if (api_ver != KVM_API_VERSION) {
		fprintf(stderr, "Got KVM api version %d, expected %d\n",
			api_ver, KVM_API_VERSION);
		throw std::runtime_error("Wrong KVM API version");
	}

	extern void initialize_vcpu_stuff(int kvm_fd);
	initialize_vcpu_stuff(fd);

	return fd;
}

}
