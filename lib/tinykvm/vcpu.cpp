#include "machine.hpp"
#include <cstring>
#include <stdexcept>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "kernel/amd64.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
#include "kernel/tss.hpp"
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

/*	for (uint32_t i = 0; i < kvm_cpuid.nent; i++) {
		auto& entry = kvm_cpuid.entries[i];
		if (entry.function == 7) {
			printf("CET = %u\n", entry.edx & (1 << 20));
		}
	}*/
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
	setup_amd64_tss(sregs,
		TSS_ADDR, memory.at(TSS_ADDR), GDT_ADDR, memory.at(GDT_ADDR));
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
	msrs.entries[0].data  = (8ull << 32) | (24ull << 48);
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[1].data  = EXCEPT_ASM_ADDR;

	if (ioctl(this->vcpu.fd, KVM_SET_MSRS, &msrs) < 0) {
		throw std::runtime_error("KVM_SET_MSRS failed");
	}
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad;

		struct kvm_msr_entry entries[2];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_FS_BASE;
	msrs.entries[1].index = AMD64_MSR_GS_BASE;

	if (ioctl(this->vcpu.fd, KVM_GET_MSRS, &msrs) < 0) {
		throw std::runtime_error("KVM_GET_MSRS failed");
	}
	return {msrs.entries[0].data, msrs.entries[1].data};
}
void Machine::set_tls_base(__u64 baseaddr)
{
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad;

		struct kvm_msr_entry entries[1];
	} msrs;
	msrs.nmsrs = 1;
	msrs.entries[0].index = AMD64_MSR_FS_BASE;
	msrs.entries[0].data  = baseaddr;

	long ret = ioctl(this->vcpu.fd, KVM_SET_MSRS, &msrs);
	if (ret <= 0) {
		throw std::runtime_error("KVM_SET_MSRS failed");
	}
	printf("set_tls_base: 0x%llX => %ld\n", baseaddr, ret);
}

void Machine::print_registers()
{
	struct kvm_sregs sregs;
	if (ioctl(this->vcpu.fd, KVM_GET_SREGS, &sregs) < 0) {
		fprintf(stderr, "Unable to retrieve registers\n");
		return;
	}

	auto regs = registers();
	printf("RIP: 0x%llX  RSP: 0x%llX\n", regs.rip, regs.rsp);
	try {
		printf("Possible return: 0x%lX\n",
			*(uint64_t *)memory.at(regs.rsp + 0x0, 8));
		printf("Possible return: 0x%lX\n",
			*(uint64_t *)memory.at(regs.rsp + 0x08, 8));
	} catch (...) {}
	printf("CS=0x%X  SS=0x%X\n", sregs.cs.selector, sregs.ss.selector);

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
	print_gdt_entries(memory.at(GDT_ADDR), 7);
#endif
}

void Machine::handle_exception(uint8_t intr)
{
	auto regs = registers();
	fprintf(stderr, "*** CPU EXCEPTION: %s\n",
		exception_name(intr));
	if (intr == 14) { // Page fault
		auto regs = registers();
		if (memory.within(regs.rsp, 8))
		{
			auto code = *(uint64_t *)memory.at(regs.rsp, 8);
			printf("Error code: 0x%lX\n", code);
			if (code & 0x01) {
				printf("* Protection violation\n");
			} else {
				printf("* Page not present\n");
			}
			if (code & 0x02) {
				printf("* Invalid write on page\n");
			}
			if (code & 0x04) {
				printf("* CPL=3 Page fault\n");
			}
			if (code & 0x08) {
				printf("* Page contains invalid bits\n");
			}
			if (code & 0x10) {
				printf("* Instruction fetch failed (NX-bit was set)\n");
			}
		} else {
			printf("Bullshit RSP: 0x%llX\n", regs.rsp);
		}
	}
	this->print_registers();
	//print_pagetables(memory, PT_ADDR);
}

long Machine::run(unsigned timeout)
{
	this->m_stopped = false;
	while(run_once());
	return 0;
}
long Machine::run_once()
{
	if (ioctl(vcpu.fd, KVM_RUN, 0) < 0) {
		throw std::runtime_error("KVM_RUN failed");
	}
	//printf("KVM interrupted\n");

	switch (vcpu.kvm_run->exit_reason) {
	case KVM_EXIT_HLT:
		throw MachineException("Shutdown! HLT?", 5);
		return 0;

	case KVM_EXIT_DEBUG:
		return KVM_EXIT_DEBUG;

	case KVM_EXIT_FAIL_ENTRY:
		throw MachineException("Failed to start guest! Misconfigured?", KVM_EXIT_FAIL_ENTRY);

	case KVM_EXIT_SHUTDOWN:
		throw MachineException("Shutdown! Triple fault?", 32);

	case KVM_EXIT_IO:
		if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT) {
		if (vcpu.kvm_run->io.port < TINYKVM_MAX_SYSCALLS) {
			this->system_call(vcpu.kvm_run->io.port);
			if (this->m_stopped) return 0;
			return KVM_EXIT_IO;
		}
		else if (vcpu.kvm_run->io.port == 0xFFFF) {
			char *p = (char *) vcpu.kvm_run;
			auto intr = *(uint8_t*) &p[vcpu.kvm_run->io.data_offset];
			/* CPU Exception */
			this->handle_exception(intr);
			throw MachineException(std::string(exception_name(intr)), intr);
		}
		fprintf(stderr,	"Unknown IO port %d\n",
			vcpu.kvm_run->io.port);
		}
		return KVM_EXIT_IO;

	case KVM_EXIT_MMIO:
		if (mmio_scall.within(vcpu.kvm_run->mmio.phys_addr, 1)) {
			unsigned scall = vcpu.kvm_run->mmio.phys_addr - mmio_scall.begin();
			system_call(scall);
			if (this->m_stopped) return 0;
			return KVM_EXIT_MMIO;
		}
		printf("Unknown MMIO write at 0x%llX\n",
			vcpu.kvm_run->mmio.phys_addr);
		//[[fallthrough]];
		return KVM_EXIT_MMIO;
	default:
		fprintf(stderr,	"Unexpected exit reason %d\n", vcpu.kvm_run->exit_reason);
		throw MachineException("Unexpected KVM exit reason",
			vcpu.kvm_run->exit_reason);
	}
}

long Machine::step_one()
{
	struct kvm_guest_debug dbg;
	dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

	if (ioctl(vcpu.fd, KVM_SET_GUEST_DEBUG, &dbg) < 0) {
		throw std::runtime_error("KVM_RUN failed");
	}

	return run_once();
}
long Machine::run_with_breakpoints(std::array<uint64_t, 4> bp)
{
	struct kvm_guest_debug dbg;
	dbg = {0};

	dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
	for (size_t i = 0; i < bp.size(); i++) {
		dbg.arch.debugreg[i] = bp[i];
		if (bp[i] != 0x0)
			dbg.arch.debugreg[7] |= 0x3 << (2 * i);
	}
	printf("Continue with BPs at 0x%lX, 0x%lX, 0x%lX and 0x%lX\n",
		bp[0], bp[1], bp[2], bp[3]);

	if (ioctl(vcpu.fd, KVM_SET_GUEST_DEBUG, &dbg) < 0) {
		throw std::runtime_error("KVM_RUN failed");
	}

	return run_once();
}

}
