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

namespace tinykvm {
	int Machine::kvm_fd = -1;
	std::array<Machine::syscall_t, TINYKVM_MAX_SYSCALLS> Machine::m_syscalls {nullptr};
	Machine::numbered_syscall_t Machine::m_unhandled_syscall = [] (Machine&, unsigned) {};
	Machine::io_callback_t Machine::m_on_input = [] (Machine&, unsigned, unsigned) {};
	Machine::io_callback_t Machine::m_on_output = [] (Machine&, unsigned, unsigned) {};
	static int kvm_open();

__attribute__ ((cold))
Machine::Machine(std::string_view binary, const MachineOptions& options)
	: m_forked {false},
	  m_binary {binary},
	  memory { vMemory::New(*this, 0x0, 0x100000, options.max_mem) },
	  m_mt   {new MultiThreading{*this}}
{
	assert(kvm_fd != -1 && "Call Machine::init() first");

	this->fd = create_kvm_vm();

	/* Disallow viewing memory below 1MB */
	install_memory(0, memory.vmem());

	this->elf_loader(options);

	this->vcpu.init(*this);
	this->setup_long_mode(nullptr);
	struct tinykvm_x86regs regs {};
	/* Store the registers, so that Machine is ready to go */
	this->setup_registers(regs);
	this->set_registers(regs);
}
Machine::Machine(const std::vector<uint8_t>& bin, const MachineOptions& opts)
	: Machine(std::string_view{(const char*)&bin[0], bin.size()}, opts) {}

Machine::Machine(const Machine& other, const MachineOptions& options)
	: m_stopped {true},
	  m_forked  {true},
	  m_binary {other.m_binary},
	  m_stack_address {other.m_stack_address},
	  m_heap_address {other.m_heap_address},
	  m_start_address {other.m_start_address},
	  memory   {*this, options, other.memory},
	  m_mm     {other.m_mm},
	  m_mt     {nullptr} //new MultiThreading{*other.m_mt}}
{
	assert(kvm_fd != -1 && "Call Machine::init() first");
	assert(other.m_prepped == true && "Call Machine::prepare_copy_on_write() first");

	this->fd = create_kvm_vm();

	/* Reuse pre-CoWed pagetable from the master machine */
	this->install_memory(0, memory.vmem());

	/* Clone PML4 page */
	auto pml4 = memory.new_page();
	std::memcpy(pml4.pmem, memory.page_at(memory.page_tables), PAGE_SIZE);
	memory.page_tables = pml4.addr;

	/* Initialize vCPU and long mode (fast path) */
	this->vcpu.init(*this);
	this->setup_long_mode(&other);
}

__attribute__ ((cold))
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

void Machine::reset_to(Machine& other)
{
	assert(m_forked);
	memory.fork_reset();

	this->m_mm = other.m_mm;

	this->setup_long_mode(&other);

	this->set_registers(other.registers());
}

uint64_t Machine::stack_push(__u64& sp, const void* data, size_t length)
{
	sp = (sp - length) & ~(uint64_t) 0x7; // maintain word alignment
	copy_to_guest(sp, data, length, true);
	return sp;
}
uint64_t Machine::stack_push_cstr(__u64& sp, const char* string)
{
	return stack_push(sp, string, strlen(string));
}

void Machine::install_memory(uint32_t idx, const VirtualMem& mem)
{
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = (mem.ptr) ? 0u : (uint32_t) KVM_MEM_READONLY,
		.guest_phys_addr = mem.physbase,
		.memory_size = mem.size,
		.userspace_addr = (uintptr_t) mem.ptr,
	};
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
	if (UNLIKELY(ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg) < 0)) {
		throw MachineException("Failed to delete guest memory region", idx);
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

void Machine::setup_registers(tinykvm_x86regs& regs)
{
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.rip = this->start_address();
	regs.rsp = this->stack_address();
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
		throw MachineException("Failed to KVM_CREATE_VM");
	}

	/*if (ioctl(fd, KVM_SET_TSS_ADDR, 0xffffd000) < 0) {
		throw std::runtime_error("Failed to KVM_SET_TSS_ADDR");
	}*/

	/*__u64 map_addr = 0xffffc000;
	if (ioctl(fd, KVM_SET_IDENTITY_MAP_ADDR, &map_addr) < 0) {
		throw std::runtime_error("Failed KVM_SET_IDENTITY_MAP_ADDR");
	}*/

	return fd;
}

}
