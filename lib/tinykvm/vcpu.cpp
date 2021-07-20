#include "machine.hpp"
#include <cassert>
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>
#include "kernel/amd64.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
#include "kernel/tss.hpp"
#include "kernel/paging.hpp"
#include "kernel/memory_layout.hpp"

namespace tinykvm {
	static struct kvm_sregs master_sregs;
	static struct kvm_xcrs master_xregs;
	static struct {
		__u32 nent;
		__u32 padding;
		struct kvm_cpuid_entry2 entries[100];
	} kvm_cpuid;
	static long vcpu_mmap_size = 0;

TINYKVM_COLD()
void initialize_vcpu_stuff(int kvm_fd)
{
	vcpu_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (vcpu_mmap_size <= 0) {
		throw MachineException("Failed to KVM_GET_VCPU_MMAP_SIZE");
	}

	/* Retrieve KVM-host CPUID features */
	kvm_cpuid.nent = sizeof(kvm_cpuid.entries) / sizeof(kvm_cpuid.entries[0]);
	if (ioctl(kvm_fd, KVM_GET_SUPPORTED_CPUID, &kvm_cpuid) < 0) {
		throw MachineException("KVM_GET_SUPPORTED_CPUID failed");
	}
}

void Machine::vCPU::init(Machine& machine)
{
	this->fd = ioctl(machine.fd, KVM_CREATE_VCPU, 0);
	if (UNLIKELY(this->fd < 0)) {
		throw MachineException("Failed to KVM_CREATE_VCPU");
	}

	this->kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(this->kvm_run == MAP_FAILED)) {
		throw MachineException("Failed to create KVM run-time mapped memory");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		throw MachineException("KVM_SET_CPUID2 failed");
	}

	static bool minit = false;
	if (!minit) {
		minit = true;
		if (ioctl(this->fd, KVM_GET_SREGS, &master_sregs) < 0) {
			throw MachineException("KVM_GET_SREGS failed");
		}
		master_sregs.cr3 = PT_ADDR;
		master_sregs.cr4 =
			CR4_PAE | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE | CR4_FSGSBASE;
		master_sregs.cr0 =
			CR0_PE | CR0_MP | CR0_ET | CR0_NE | CR0_AM | CR0_PG | CR0_WP;
		master_sregs.efer =
			EFER_SCE | EFER_LME | EFER_LMA | EFER_NXE;
		setup_amd64_segment_regs(master_sregs, GDT_ADDR);
		setup_amd64_tss_regs(master_sregs, TSS_ADDR);
		setup_amd64_exception_regs(master_sregs, IDT_ADDR);

		if (ioctl(this->fd, KVM_GET_XCRS, &master_xregs) < 0) {
			throw MachineException("KVM_GET_XCRS failed");
		}
		/* Enable AVX instructions */
		master_xregs.xcrs[0].xcr = 0;
		master_xregs.xcrs[0].value |= 0x7; // FPU, SSE, YMM
		master_xregs.nr_xcrs = 1;
	}
}

void Machine::vCPU::deinit()
{
	if (this->fd > 0) {
		close(this->fd);
	}
	if (this->kvm_run != nullptr) {
		munmap(this->kvm_run, vcpu_mmap_size);
	}
}

TINYKVM_COLD()
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
		throw MachineException("KVM_SET_REGS failed");
	}
	return regs;
}
void Machine::vCPU::assign_registers(const struct tinykvm_x86regs& regs)
{
	if (ioctl(this->fd, KVM_SET_REGS, &regs) < 0) {
		throw MachineException("KVM_SET_REGS failed");
	}
}
void Machine::vCPU::get_special_registers(struct kvm_sregs& sregs) const
{
	if (ioctl(this->fd, KVM_GET_SREGS, &sregs) < 0) {
		throw MachineException("KVM_GET_SREGS failed");
	}
}
void Machine::vCPU::set_special_registers(const struct kvm_sregs& sregs)
{
	if (ioctl(this->fd, KVM_SET_SREGS, &sregs) < 0) {
		throw MachineException("KVM_GET_SREGS failed");
	}
}

void Machine::reset_special_regs()
{
	struct kvm_sregs sregs;
	get_special_registers(sregs);

	setup_amd64_segment_regs(sregs, GDT_ADDR);

	set_special_registers(sregs);
}

std::string_view Machine::io_data() const
{
	char *p = (char *) vcpu.kvm_run;
	return {&p[vcpu.kvm_run->io.data_offset], vcpu.kvm_run->io.size};
}

void Machine::setup_long_mode(const Machine* other)
{
	if (other == nullptr)
	{
		setup_amd64_exceptions(
			IDT_ADDR, memory.at(IDT_ADDR), memory.at(INTR_ASM_ADDR));
		setup_amd64_segments(GDT_ADDR, memory.at(GDT_ADDR));
		setup_amd64_tss(TSS_ADDR, memory.at(TSS_ADDR), memory.at(GDT_ADDR));

		uint64_t last_page = setup_amd64_paging(
			memory, INTR_ASM_ADDR, IST_ADDR, m_binary);
		this->ptmem = MemRange::New("Page tables",
			memory.page_tables, last_page - memory.page_tables);

		vcpu.set_special_registers(master_sregs);
	}
	else
	{
		/* Inherit the special registers of the master machine */
		struct kvm_sregs sregs;
		other->vcpu.get_special_registers(sregs);

		/* Page table entry will be cloned at the start */
		sregs.cr3 = memory.page_tables;

		vcpu.set_special_registers(sregs);

		/* Zero a new page for IST stack */
		memory.get_writable_page(IST_ADDR, true);

#ifndef NDEBUG
		/* It shouldn't be identity-mapped anymore */
		assert(translate(IST_ADDR) != IST_ADDR);
		//printf("Translate 0x%lX => 0x%lX\n", IST_ADDR, translate(IST_ADDR));
		page_at(memory, IST_ADDR, [] (auto, auto& entry, auto) {
			assert(entry & (PDE64_PRESENT | PDE64_RW | PDE64_NX));
			(void) entry;
		});
		//print_pagetables(this->memory);
#endif
	}

	/* Extended control registers */
	if (ioctl(this->vcpu.fd, KVM_SET_XCRS, &master_xregs) < 0) {
		throw MachineException("KVM_SET_XCRS failed");
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
	msrs.entries[1].data  = interrupt_header().vm64_syscall;

	if (ioctl(this->vcpu.fd, KVM_SET_MSRS, &msrs) < 2) {
		throw MachineException("KVM_SET_MSRS: failed to set STAR/LSTAR");
	}
}

std::pair<__u64, __u64> Machine::get_fsgs() const
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);

	return {sregs.fs.base, sregs.gs.base};
}
void Machine::set_tls_base(__u64 baseaddr)
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);

	sregs.fs.base = baseaddr;

	vcpu.set_special_registers(sregs);
}

TINYKVM_COLD()
void Machine::print_registers()
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);

	printf("CR0: 0x%llX  CR3: 0x%llX\n", sregs.cr0, sregs.cr3);
	printf("CR2: 0x%llX  CR4: 0x%llX\n", sregs.cr2, sregs.cr4);

	auto regs = registers();
	printf("RAX: 0x%llX  RBX: 0x%llX  RCX: 0x%llX\n", regs.rax, regs.rbx, regs.rcx);
	printf("RDX: 0x%llX  RSI: 0x%llX  RDI: 0x%llX\n", regs.rdx, regs.rsi, regs.rdi);
	printf("RIP: 0x%llX  RBP: 0x%llX  RSP: 0x%llX\n", regs.rip, regs.rbp, regs.rsp);

	printf("SS: 0x%X  CS: 0x%X  DS: 0x%X  FS: 0x%X  GS: 0x%X\n",
		sregs.ss.selector, sregs.cs.selector, sregs.ds.selector, sregs.fs.selector, sregs.gs.selector);

	try {
		printf("Return RIP: 0x%lX\n",
			*(uint64_t *)memory.at(regs.rsp+8, 8));
		printf("Return stack: 0x%lX\n",
			*(uint64_t *)memory.at(regs.rsp+32, 8));
	} catch (...) {}

#if 0
	print_pagetables(memory);
#endif
#if 0
	printf("CR0 PE=%llu MP=%llu EM=%llu\n",
		sregs.cr0 & 1, (sregs.cr0 >> 1) & 1, (sregs.cr0 >> 2) & 1);
	printf("CR4 OSFXSR=%llu OSXMMEXCPT=%llu OSXSAVE=%llu\n",
		(sregs.cr4 >> 9) & 1, (sregs.cr4 >> 10) & 1, (sregs.cr4 >> 18) & 1);
#endif
#if 0
	printf("IDT: 0x%llX (Size=%x)\n", sregs.idt.base, sregs.idt.limit);
	print_exception_handlers(memory.at(sregs.idt.base));
#endif
#if 0
	print_gdt_entries(memory.at(sregs.gdt.base), 7);
#endif
}

TINYKVM_COLD()
void Machine::handle_exception(uint8_t intr)
{
	auto regs = registers();
	// Page fault
	if (intr == 14) {
		struct kvm_sregs sregs;
		get_special_registers(sregs);
		fprintf(stderr, "*** %s on address 0x%llX\n",
			exception_name(intr), sregs.cr2);
		if (memory.within(regs.rsp, 8))
		{
			auto code = *(uint64_t *)memory.at(regs.rsp, 8);
			printf("Error code: 0x%lX (%s)\n", code,
				(code & 0x02) ? "memory write" : "memory read");
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
	} else {
		fprintf(stderr, "*** CPU EXCEPTION: %s\n",
			exception_name(intr));
	}
	this->print_registers();
	//print_pagetables(memory, PT_ADDR);
}

void Machine::run(unsigned timeout)
{
	this->m_stopped = false;
	while(run_once());
}

long Machine::run_once()
{
	if (ioctl(vcpu.fd, KVM_RUN, 0) < 0) {
		/* NOTE: This is probably EINTR */
		throw MachineException("KVM_RUN failed");
	}

	switch (vcpu.kvm_run->exit_reason) {
	case KVM_EXIT_HLT:
		throw MachineException("Shutdown! HLT?", 5);

	case KVM_EXIT_DEBUG:
		return KVM_EXIT_DEBUG;

	case KVM_EXIT_FAIL_ENTRY:
		throw MachineException("Failed to start guest! Misconfigured?", KVM_EXIT_FAIL_ENTRY);

	case KVM_EXIT_SHUTDOWN:
		throw MachineException("Shutdown! Triple fault?", 32);

	case KVM_EXIT_IO:
		if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT) {
		if (vcpu.kvm_run->io.port == 0x0) {
			const char* data = ((char *)vcpu.kvm_run) + vcpu.kvm_run->io.data_offset;
			const uint16_t intr = *(uint16_t *)data;
			if (intr != 0xFFFF) {
				this->system_call(intr);
				if (this->m_stopped) return 0;
				return KVM_EXIT_IO;
			} else {
				this->m_stopped = true;
				this->m_userspaced = true;
				return 0;
			}
		}
		else if (vcpu.kvm_run->io.port < 0x80) {
			this->system_call(vcpu.kvm_run->io.port);
			if (this->m_stopped) return 0;
			return KVM_EXIT_IO;
		}
		else if (vcpu.kvm_run->io.port < 0xFF) {
			auto intr = vcpu.kvm_run->io.port - 0x80;
			if (intr == 14)
			{
				/* Page fault handling */
				struct kvm_sregs sregs;
				get_special_registers(sregs);
				fprintf(stderr, "*** %s on address 0x%llX\n",
					exception_name(intr), sregs.cr2);

				const uint64_t addr = sregs.cr2 & ~(uint64_t) 0x8000000000000FFF;
				memory.get_writable_page(addr, false);

				return KVM_EXIT_IO;
			}
			/* CPU Exception */
			this->handle_exception(intr);
			throw MachineException(exception_name(intr), intr);
		}
		fprintf(stderr,	"Unknown IO port %d\n",
			vcpu.kvm_run->io.port);
		}
		return KVM_EXIT_IO;

	case KVM_EXIT_MMIO:
		if (mmio_scall.within(vcpu.kvm_run->mmio.phys_addr, 1)) {
			unsigned scall = vcpu.kvm_run->mmio.phys_addr - mmio_scall.begin();
			system_call(scall);
			return (this->m_stopped) ? 0 : KVM_EXIT_MMIO;
		}
		printf("Unknown MMIO write at 0x%llX\n",
			vcpu.kvm_run->mmio.phys_addr);
		return KVM_EXIT_MMIO;

	case KVM_EXIT_INTERNAL_ERROR:
		throw MachineException("KVM internal error");

	default:
		fprintf(stderr,	"Unexpected exit reason %d\n", vcpu.kvm_run->exit_reason);
		throw MachineException("Unexpected KVM exit reason",
			vcpu.kvm_run->exit_reason);
	}
}

long Machine::return_value() const
{
	/* TODO: Return vcpu.kvm_run->s.regs.regs.rdi */
	auto regs = registers();
	return regs.rdi;
}

TINYKVM_COLD()
long Machine::step_one()
{
	struct kvm_guest_debug dbg;
	dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

	if (ioctl(vcpu.fd, KVM_SET_GUEST_DEBUG, &dbg) < 0) {
		throw MachineException("KVM_RUN failed");
	}

	return run_once();
}

TINYKVM_COLD()
long Machine::run_with_breakpoints(std::array<uint64_t, 4> bp)
{
	struct kvm_guest_debug dbg {};

	dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_HW_BP;
	for (size_t i = 0; i < bp.size(); i++) {
		dbg.arch.debugreg[i] = bp[i];
		if (bp[i] != 0x0)
			dbg.arch.debugreg[7] |= 0x3 << (2 * i);
	}
	//printf("Continue with BPs at 0x%lX, 0x%lX, 0x%lX and 0x%lX\n",
	//	bp[0], bp[1], bp[2], bp[3]);

	if (ioctl(vcpu.fd, KVM_SET_GUEST_DEBUG, &dbg) < 0) {
		throw MachineException("KVM_RUN failed");
	}

	return run_once();
}

void Machine::prepare_copy_on_write()
{
	assert(this->m_prepped == false);
	this->m_prepped = true;
	foreach_page_makecow(this->memory);
	//print_pagetables(this->memory);
}

Machine::address_t Machine::exit_address() const noexcept {
	return interrupt_header().vm64_rexit;
}

}
