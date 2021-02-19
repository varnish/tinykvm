#include "machine.hpp"

#include "amd64.hpp"
#include "common.hpp"
#include <cstring>
#include <fcntl.h>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <stdexcept>

namespace tinykvm {
	int Machine::kvm_fd = -1;
	static int kvm_open();

Machine::Machine(std::string_view binary, uint64_t max_mem)
{
	if (UNLIKELY(kvm_fd == -1)) {
		kvm_fd = kvm_open();
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

	/* TODO: Needs improvements */
	this->ptmem = MemRange::New("Page tables", PT_ADDR, 0x8000);

	const size_t binsize = (binary.size() + 0xFFF) & ~0xFFF;
	this->romem = MemRange::New("Binary", 0x200000, binsize);
	this->rwmem = MemRange::New("Heap", 0x400000, max_mem - 0x400000);

	this->memory = vMemory::New(0x0, max_mem);
	std::memcpy(memory.at(romem.physbase), binary.data(), binary.size());

	this->mmio_scall = MemRange::New("System calls", 0xffffa000, 0x1000);

	if (UNLIKELY(install_memory(0, this->memory) < 0)) {
		throw std::runtime_error("Failed to install guest memory region");
	}
//	if (UNLIKELY(install_memory(1, this->mmio_scall) < 0)) {
//		throw std::runtime_error("Failed to install syscall MMIO memory region");
//	}

	this->vcpu.init(*this);
	this->setup_long_mode();
}
Machine::Machine(const std::vector<uint8_t>& binary, uint64_t max_mem)
	: Machine(std::string_view{(const char*)&binary[0], binary.size()}, max_mem) {}

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

void Machine::reset()
{
	memory.reset();
}

Machine::~Machine()
{
	if (fd > 0) {
		close(fd);
		close(vcpu.fd);
	}
}

void Machine::system_call(unsigned idx)
{
	if (idx < m_syscalls.size()) {
		const auto handler = m_syscalls[idx];
		if (handler != nullptr) {
			handler(*this);
			return;
		}
	}
	m_unhandled_syscall(*this, idx);
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

	return fd;
}

}
