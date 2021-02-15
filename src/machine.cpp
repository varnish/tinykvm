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

Machine::Machine(std::span<const uint8_t> binary, uint64_t max_mem)
{
	if (UNLIKELY(kvm_fd == -1)) {
		kvm_fd = kvm_open();
	}

	this->fd = ioctl(kvm_fd, KVM_CREATE_VM, 0);
	if (UNLIKELY(this->fd < 0)) {
		throw std::runtime_error("Failed to KVM_CREATE_VM");
	}

	if (ioctl(this->fd, KVM_SET_TSS_ADDR, 0xfffbd000) < 0) {
		throw std::runtime_error("Failed to KVM_SET_TSS_ADDR");
	}

	/* TODO: Needs improvements */
	this->ptmem = vMemory::New("Page tables", 0x2000, 0x8000);

	const size_t binsize = (binary.size() + 0xFFF) & ~0xFFF;
	this->romem =
		vMemory::New("Binary", 0x100000, binsize);
	std::memcpy(romem.ptr, binary.data(), binary.size());

	this->rwmem =
		vMemory::New("Heap/stack", 0x200000, max_mem);

	if (UNLIKELY(install_memory(0, this->ptmem) < 0)) {
		throw std::runtime_error("Failed to install memory region");
	}
	if (UNLIKELY(install_memory(1, this->romem) < 0)) {
		throw std::runtime_error("Failed to install memory region");
	}
	if (UNLIKELY(install_memory(2, this->rwmem) < 0)) {
		throw std::runtime_error("Failed to install memory region");
	}

	this->vcpu.init(*this);
	this->setup_long_mode();
}

int Machine::install_memory(uint32_t idx, vMemory mem)
{
	const struct kvm_userspace_memory_region memreg {
		.slot = idx,
		.flags = 0,
		.guest_phys_addr = mem.physbase,
		.memory_size = mem.size,
		.userspace_addr = (uintptr_t) mem.ptr,
	};
	return ioctl(this->fd, KVM_SET_USER_MEMORY_REGION, &memreg);
}

void Machine::reset()
{
	rwmem.reset();
}

Machine::~Machine()
{
	if (fd > 0) {
		close(fd);
		close(vcpu.fd);
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

	return fd;
}

}
