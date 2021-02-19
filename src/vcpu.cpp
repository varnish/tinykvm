#include "machine.hpp"
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdexcept>
#include "amd64.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
#define ENABLE_GUEST_STDOUT
#define SYSCALL_ADDRESS_BEG   0xffffa000
#define SYSCALL_ADDRESS_END   0xffffb000
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

void Machine::setup_call(uint64_t rip, uint64_t rsp)
{
	struct kvm_regs regs;
	memset(&regs, 0, sizeof(regs));
	/* Set IOPL=3 to allow I/O instructions */
	regs.rflags = 2 | (3 << 12);
	regs.rip = rip;
	regs.rsp = rsp;

	if (ioctl(this->vcpu.fd, KVM_SET_REGS, &regs) < 0) {
		throw std::runtime_error("KVM_SET_REGS failed");
	}
}

long Machine::run(double timeout)
{
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
			if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT
				&& vcpu.kvm_run->io.port == 0xE9) {
#ifdef ENABLE_GUEST_STDOUT
				char *p = (char *) vcpu.kvm_run;
				fwrite(p + vcpu.kvm_run->io.data_offset,
					   vcpu.kvm_run->io.size, 1, stdout);
				fflush(stdout);
#endif
				continue;
			}
			if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT
				&& vcpu.kvm_run->io.port < 32) {
				/* CPU Exception */
				this->handle_exception(vcpu.kvm_run->io.port);
				return -1;
			}
			fprintf(stderr,	"Unknown IO port %d\n",
				vcpu.kvm_run->io.port);
			continue;
		case KVM_EXIT_MMIO:
			if (vcpu.kvm_run->mmio.phys_addr >= SYSCALL_ADDRESS_BEG
				&& vcpu.kvm_run->mmio.phys_addr < SYSCALL_ADDRESS_END) {
				unsigned scall = vcpu.kvm_run->mmio.phys_addr - SYSCALL_ADDRESS_BEG;
				system_call(scall);
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
	pd[0] = PDE64_PRESENT | PDE64_USER | PDE64_RW | PDE64_NX | low1_addr;

	lowpage[0] = 0; /* Null-page at 0x0 */
	for (unsigned i = 1; i < 256; i++) {
		/* Kernel area < 1MB */
		lowpage[i] = PDE64_PRESENT | PDE64_RW | PDE64_NX | (i << 12);
	}
	for (unsigned i = 256; i < 512; i++) {
		/* Stack area 1MB -> 2MB */
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
	setup_amd64_exceptions(sregs, 0x200060);

	if (ioctl(this->vcpu.fd, KVM_SET_SREGS, &sregs) < 0) {
		throw std::runtime_error("KVM_SET_SREGS failed");
	}
}

void Machine::setup_amd64_exceptions(struct kvm_sregs& sregs, uint64_t ehandler)
{
	char* idt = memory.at(IDT_ADDR);
	sregs.idt.base  = IDT_ADDR;
	sregs.idt.limit = sizeof_idt() - 1;
	for (int i = 0; i <= 20; i++) {
		if (i == 15) continue;
		//printf("Exception handler %d at 0x%lX\n", i, ehandler + i * 16);
		set_exception_handler(idt, i, ehandler + i * 16);
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

void Machine::handle_exception(uint8_t exception)
{
	fprintf(stderr, "*** CPU EXCEPTION: %s\n",
		exception_name(exception));
	this->print_registers();
}

}
