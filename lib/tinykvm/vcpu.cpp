#include "machine.hpp"
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdexcept>
#include "amd64.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
static struct kvm_sregs master_sregs;

namespace tinykvm {
void Machine::vCPU::init(Machine& machine)
{
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, 0);
	if (this->fd < 0) {
		throw std::runtime_error("Failed to KVM_CREATE_VCPU");
	}

	const int vcpu_mmap_size =
		ioctl(Machine::kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		throw std::runtime_error("Failed to KVM_GET_VCPU_MMAP_SIZE");
	}

	this->kvm_run = (struct kvm_run*) mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (this->kvm_run == MAP_FAILED) {
		throw std::runtime_error("Failed to create KVM run-time mapped memory");
	}
}
void Machine::vCPU::print_address_info(uint64_t addr)
{
	struct kvm_translation tr;
	tr.linear_address = addr;
	ioctl(this->fd, KVM_TRANSLATE, &tr);
	printf("0x%llX translates to 0x%llX\n",
		tr.linear_address, tr.physical_address);
	printf("* %s\n", tr.valid ? "Valid" : "Invalid");
}

tinykvm_x86regs Machine::vCPU::registers() const
{
	struct tinykvm_x86regs regs;
	if (ioctl(this->fd, KVM_GET_REGS, &regs) < 0) {
		throw std::runtime_error("KVM_SET_REGS failed");
	}
	return regs;
}
void Machine::vCPU::assign_registers(const struct tinykvm_x86regs& regs)
{
	if (ioctl(this->fd, KVM_SET_REGS, &regs) < 0) {
		throw std::runtime_error("KVM_SET_REGS failed");
	}
}

std::string_view Machine::io_data() const
{
	char *p = (char *) vcpu.kvm_run;
	return {&p[vcpu.kvm_run->io.data_offset], vcpu.kvm_run->io.size};
}

long Machine::run(unsigned timeout)
{
	this->stopped = false;
	for (;;) {
		if (ioctl(vcpu.fd, KVM_RUN, 0) < 0) {
			throw std::runtime_error("KVM_RUN failed");
		}
		//printf("KVM interrupted\n");

		switch (vcpu.kvm_run->exit_reason) {
		case KVM_EXIT_HLT:
			fprintf(stderr,	"KVM_EXIT_HLT\n");
			return 0;

		case KVM_EXIT_SHUTDOWN:
			fprintf(stderr,	"Shutdown! Triple fault?\n");
			return 0;

		case KVM_EXIT_IO:
			if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT) {
			if (vcpu.kvm_run->io.port < TINYKVM_MAX_SYSCALLS) {
				this->system_call(vcpu.kvm_run->io.port);
				if (this->stopped) return 0;
				continue;
			}
			else if (vcpu.kvm_run->io.port == 0xFFFF) {
				char *p = (char *) vcpu.kvm_run;
				auto intr = *(uint8_t*) &p[vcpu.kvm_run->io.data_offset];
				/* CPU Exception */
				struct kvm_regs regs;
				if (ioctl(vcpu.fd, KVM_GET_REGS, &regs) < 0) {
					throw std::runtime_error("CPU exception: KVM_GET_REGS failed");
				}
				this->handle_exception(intr, regs);
				return -1;
			}
			fprintf(stderr,	"Unknown IO port %d\n",
				vcpu.kvm_run->io.port);
			}
			continue;
		case KVM_EXIT_MMIO:
			if (mmio_scall.within(vcpu.kvm_run->mmio.phys_addr, 1)) {
				unsigned scall = vcpu.kvm_run->mmio.phys_addr - mmio_scall.begin();
				system_call(scall);
				if (this->stopped) return 0;
				continue;
			}
			printf("Unknown MMIO write at 0x%llX\n",
				vcpu.kvm_run->mmio.phys_addr);
			//[[fallthrough]];
			continue;
		default:
			fprintf(stderr,	"Got exit_reason %d,"
				" expected KVM_EXIT_HLT (%d)\n",
				vcpu.kvm_run->exit_reason, KVM_EXIT_HLT);
			throw std::runtime_error("Unexpected KVM exit reason");
		}
	}
	return -1;
}

void Machine::setup_long_mode()
{
	static bool init = false;
	if (!init) {
		init = true;
		if (ioctl(this->vcpu.fd, KVM_GET_SREGS, &master_sregs) < 0) {
			throw std::runtime_error("KVM_GET_SREGS failed");
		}
	}

	auto sregs = master_sregs;

	// guest physical
	const uint64_t pml4_addr = PT_ADDR;
	const uint64_t pdpt_addr = pml4_addr + 0x1000;
	const uint64_t pd_addr   = pml4_addr + 0x2000;
	const uint64_t mmio_addr = pml4_addr + 0x4000;
	const uint64_t low1_addr = pml4_addr + 0x5000;
	// userspace
	char* pagetable = memory.at(PT_ADDR);
	auto* pml4 = (uint64_t*) (pagetable + 0x0);
	auto* pdpt = (uint64_t*) (pagetable + 0x1000);
	auto* pd   = (uint64_t*) (pagetable + 0x2000);
	auto* mmio = (uint64_t*) (pagetable + 0x4000);
	auto* lowpage = (uint64_t*) (pagetable + 0x5000);

	pml4[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pdpt_addr;
	pdpt[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | pd_addr;
	pdpt[3] = PDE64_PRESENT | PDE64_USER | PDE64_RW | mmio_addr;
	pd[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | low1_addr;

	lowpage[0] = 0; /* Null-page at 0x0 */
	/* Kernel area < 1MB */
	for (unsigned i = 1; i < 256; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_RW | PDE64_NX | (i << 12);
	}
	/* Exception handlers */
	lowpage[EXCEPT_ASM_ADDR >> 12] = PDE64_PRESENT | PDE64_USER | EXCEPT_ASM_ADDR;
	/* Stack area 1MB -> 2MB */
	for (unsigned i = 256; i < 512; i++) {
		lowpage[i] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | (i << 12);
	}

	/* ELF executable area */
	for (unsigned i = 1; i < 512; i++) {
		pd[i] = PDE64_PRESENT | PDE64_PS | PDE64_USER | (i << 21);
	}

	// MMIO system calls
	mmio[511] = PDE64_PRESENT | PDE64_PS | PDE64_USER | PDE64_RW | PDE64_NX | 0xff000000 | (511 << 21);

	sregs.cr3 = pml4_addr;
	sregs.cr4 = CR4_PAE;
	sregs.cr0
		= CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.efer = EFER_LME | EFER_LMA | EFER_NXE;

	setup_amd64_segments(sregs, GDT_ADDR, memory.at(GDT_ADDR));
	setup_amd64_exceptions(sregs,
		IDT_ADDR, memory.at(IDT_ADDR), EXCEPT_ASM_ADDR, memory.at(EXCEPT_ASM_ADDR));

	if (ioctl(this->vcpu.fd, KVM_SET_SREGS, &sregs) < 0) {
		throw std::runtime_error("KVM_SET_SREGS failed");
	}
}

void Machine::print_registers()
{
	struct kvm_sregs sregs;
	if (ioctl(this->vcpu.fd, KVM_GET_SREGS, &sregs) < 0) {
		throw std::runtime_error("KVM_GET_SREGS failed");
	}

	printf("IDT: 0x%llX (Size=%x)\n", sregs.idt.base, sregs.idt.limit);
	//print_exception_handlers(memory.at(IDT_ADDR));
	print_gdt_entries(memory.at(GDT_ADDR), 3);
}

void Machine::handle_exception(uint8_t intr, const struct kvm_regs& regs)
{
	fprintf(stderr, "*** CPU EXCEPTION: %s\n",
		exception_name(intr));
	this->print_registers();
}

}
