#include "machine.hpp"
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdexcept>
#include "kernel/amd64.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
#include "kernel/paging.hpp"
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

	/* Retrieve KVM-host CPUID features */
	struct {
		__u32 nent;
		__u32 padding;
		struct kvm_cpuid_entry2 entries[100];
	} kvm_cpuid;
	kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);
	if (ioctl(Machine::kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid) < 0) {
		throw std::runtime_error("KVM_GET_SUPPORTED_CPUID failed");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		throw std::runtime_error("KVM_SET_CPUID2 failed");
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
	setup_amd64_paging(memory, PT_ADDR, EXCEPT_ASM_ADDR, m_binary);

	sregs.cr3 = PT_ADDR;
	sregs.cr4 = CR4_TSD | CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE;
	sregs.cr0 =
		CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_WP | CR0_AM | CR0_PG;
	sregs.efer = EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;

	setup_amd64_segments(sregs, GDT_ADDR, memory.at(GDT_ADDR));
	setup_amd64_exceptions(sregs,
		IDT_ADDR, memory.at(IDT_ADDR), EXCEPT_ASM_ADDR, memory.at(EXCEPT_ASM_ADDR));

	if (ioctl(this->vcpu.fd, KVM_SET_SREGS, &sregs) < 0) {
		throw std::runtime_error("KVM_SET_SREGS failed");
	}

	struct kvm_xcrs xregs;
	if (ioctl(this->vcpu.fd, KVM_GET_XCRS, &xregs) < 0) {
		throw std::runtime_error("KVM_GET_XCRS failed");
	}

	/* Enable AVX instructions */
	xregs.xcrs[0].xcr = 0;
	xregs.xcrs[0].value |= 0x7; // FPU, SSE, YMM
	xregs.nr_xcrs = 1;

	if (ioctl(this->vcpu.fd, KVM_SET_XCRS, &xregs) < 0) {
		throw std::runtime_error("KVM_SET_XCRS failed");
	}

	/* Enable SYSCALL/SYSRET instructions */
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad;

		struct kvm_msr_entry entries[2];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_STAR;
	msrs.entries[0].data  = 0x0810081000000000;
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[1].data  = EXCEPT_ASM_ADDR;

	if (ioctl(this->vcpu.fd, KVM_SET_MSRS, &msrs) < 0) {
		throw std::runtime_error("KVM_SET_MSRS failed");
	}
}

void Machine::set_tls_base(__u64 baseaddr)
{
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad;

		struct kvm_msr_entry entries[2];
	} msrs;
	msrs.nmsrs = 1;
	msrs.entries[0].index = AMD64_MSR_FS_BASE;
	msrs.entries[0].data  = baseaddr;

	if (ioctl(this->vcpu.fd, KVM_SET_MSRS, &msrs) < 0) {
		throw std::runtime_error("KVM_SET_MSRS failed");
	}
}

void Machine::print_registers()
{
	struct kvm_sregs sregs;
	if (ioctl(this->vcpu.fd, KVM_GET_SREGS, &sregs) < 0) {
		throw std::runtime_error("KVM_GET_SREGS failed");
	}

	auto regs = registers();
	printf("RIP: 0x%llX  RSP: 0x%llX\n", regs.rip, regs.rsp);
	try {
		auto stk = *(uint64_t *)memory.safely_at(regs.rsp, 8);
		printf("Stack contents: 0x%lX\n", stk);
		printf("Possible return: 0x%lX\n",
			*(uint64_t *)memory.safely_at(regs.rsp + 0x0, 8));
		printf("Possible return: 0x%lX\n",
			*(uint64_t *)memory.safely_at(regs.rsp + 0x08, 8));
		printf("Possible return: 0x%lX\n",
			*(uint64_t *)memory.safely_at(regs.rsp + 0x10, 8));
	} catch (...) {}

#if 0
	printf("CR0 PE=%llu MP=%llu EM=%llu\n",
		sregs.cr0 & 1, (sregs.cr0 >> 1) & 1, (sregs.cr0 >> 2) & 1);
	printf("CR4 OSFXSR=%llu OSXMMEXCPT=%llu OSXSAVE=%llu\n",
		(sregs.cr4 >> 9) & 1, (sregs.cr4 >> 10) & 1, (sregs.cr4 >> 18) & 1);
#endif
#if 0
	printf("IDT: 0x%llX (Size=%x)\n", sregs.idt.base, sregs.idt.limit);
	print_exception_handlers(memory.at(IDT_ADDR));
#endif
#if 0
	print_gdt_entries(memory.at(GDT_ADDR), 3);
#endif
}

void Machine::handle_exception(uint8_t intr, const struct kvm_regs& regs)
{
	fprintf(stderr, "*** CPU EXCEPTION: %s\n",
		exception_name(intr));
	this->print_registers();
}

}
