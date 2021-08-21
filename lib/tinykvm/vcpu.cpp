#include "machine.hpp"

#include <cassert>
#include <cstring>
#include <linux/kvm.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "page_streaming.hpp"
#include "kernel/amd64.hpp"
//#include "kernel/lapic.hpp"
#include "kernel/idt.hpp"
#include "kernel/gdt.hpp"
#include "kernel/tss.hpp"
#include "kernel/paging.hpp"
#include "kernel/memory_layout.hpp"
#include "kernel/usercode.hpp"
//#define VERBOSE_PAGE_FAULTS
extern "C" int close(int);

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
		machine_exception("Failed to KVM_CREATE_VCPU");
	}

	this->kvm_run = (struct kvm_run*) ::mmap(NULL, vcpu_mmap_size,
		PROT_READ | PROT_WRITE, MAP_SHARED, this->fd, 0);
	if (UNLIKELY(this->kvm_run == MAP_FAILED)) {
		machine_exception("Failed to create KVM run-time mapped memory");
	}

	/* Assign CPUID features to guest */
	if (ioctl(this->fd, KVM_SET_CPUID2, &kvm_cpuid) < 0) {
		machine_exception("KVM_SET_CPUID2 failed");
	}

	static bool minit = false;
	if (!minit) {
		minit = true;
		if (ioctl(this->fd, KVM_GET_SREGS, &master_sregs) < 0) {
			machine_exception("KVM_GET_SREGS failed");
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
			machine_exception("KVM_GET_XCRS failed");
		}
		/* Enable AVX instructions */
		master_xregs.xcrs[0].xcr = 0;
		master_xregs.xcrs[0].value |= 0x7; // FPU, SSE, YMM
		master_xregs.nr_xcrs = 1;
	}

	/* Extended control registers */
	if (ioctl(this->fd, KVM_SET_XCRS, &master_xregs) < 0) {
		machine_exception("KVM_SET_XCRS failed");
	}

	/* Enable SYSCALL/SYSRET instructions */
	struct {
		__u32 nmsrs; /* number of msrs in entries */
		__u32 pad;

		struct kvm_msr_entry entries[2];
	} msrs;
	msrs.nmsrs = 2;
	msrs.entries[0].index = AMD64_MSR_STAR;
	msrs.entries[1].index = AMD64_MSR_LSTAR;
	msrs.entries[0].data  = (0x8LL << 32) | (0x1BLL << 48);
	msrs.entries[1].data  = interrupt_header().vm64_syscall;

	if (ioctl(this->fd, KVM_SET_MSRS, &msrs) < 2) {
		machine_exception("KVM_SET_MSRS: failed to set STAR/LSTAR");
	}

	/* LAPIC
	msrs.entries[0].index = AMD64_MSR_APICBASE;
	msrs.entries[0].data  = 0xfee00000 | AMD64_MSR_XAPIC_ENABLE;
	msrs.nmsrs = 1;

	if (ioctl(this->vcpu.fd, KVM_SET_MSRS, &msrs) < 1) {
		machine_exception("KVM_SET_MSRS: failed to enable xAPIC");
	}

	//struct local_apic lapic {};
	struct kvm_lapic_state lapic;
	if (ioctl(this->vcpu.fd, KVM_GET_LAPIC, &lapic)) {
		machine_exception("KVM_GET_LAPIC: failed to get initial LAPIC");
	}

	//lapic.lvt_lint0.delivery_mode = AMD64_APIC_MODE_EXTINT;
	//lapic.lvt_lint1.delivery_mode = AMD64_APIC_MODE_NMI;

	if (ioctl(this->vcpu.fd, KVM_SET_LAPIC, &lapic)) {
		machine_exception("KVM_SET_LAPIC: failed to set initial LAPIC");
	}*/
}

void Machine::vCPU::deinit()
{
	if (this->fd > 0) {
		close(this->fd);
	}
	if (this->kvm_run != nullptr) {
		munmap(this->kvm_run, vcpu_mmap_size);
	}
	delete cached_sregs;
}

tinykvm_x86regs Machine::vCPU::registers() const
{
	struct tinykvm_x86regs regs;
	if (ioctl(this->fd, KVM_GET_REGS, &regs) < 0) {
		machine_exception("KVM_SET_REGS failed");
	}
	return regs;
}
void Machine::vCPU::assign_registers(const struct tinykvm_x86regs& regs)
{
	if (ioctl(this->fd, KVM_SET_REGS, &regs) < 0) {
		machine_exception("KVM_SET_REGS failed");
	}
}
void Machine::vCPU::get_special_registers(struct kvm_sregs& sregs) const
{
	if (ioctl(this->fd, KVM_GET_SREGS, &sregs) < 0) {
		machine_exception("KVM_GET_SREGS failed");
	}
}
void Machine::vCPU::set_special_registers(const struct kvm_sregs& sregs)
{
	if (ioctl(this->fd, KVM_SET_SREGS, &sregs) < 0) {
		machine_exception("KVM_GET_SREGS failed");
	}
}

std::string_view Machine::io_data() const
{
	char *p = (char *) vcpu.kvm_run;
	return {&p[vcpu.kvm_run->io.data_offset], vcpu.kvm_run->io.size};
}

void Machine::setup_long_mode(const Machine* other, const MachineOptions& options)
{
	if (other == nullptr)
	{
		setup_amd64_exceptions(
			IDT_ADDR, memory.at(IDT_ADDR), memory.at(INTR_ASM_ADDR));
		setup_amd64_segments(GDT_ADDR, memory.at(GDT_ADDR));
		setup_amd64_tss(TSS_ADDR, memory.at(TSS_ADDR), memory.at(GDT_ADDR));
		/* Userspace entry/exit code */
		setup_vm64_usercode(memory.at(USER_ASM_ADDR));

		uint64_t last_page = setup_amd64_paging(memory, m_binary);
		//this->ptmem = MemRange::New("Page tables",
		//	memory.page_tables, last_page - memory.page_tables);
		(void) last_page;

		vcpu.set_special_registers(master_sregs);
	}
	else if (LIKELY(!options.linearize_memory))
	{
		/* Clone master PML4 page */
		auto pml4 = memory.new_page(0x0);
		tinykvm::page_duplicate(pml4.pmem, other->memory.page_at(other->memory.page_tables));
		memory.page_tables = pml4.addr;

		/* Zero a new page for IST stack */
		memory.get_writable_page(IST_ADDR, true);

		/* Inherit the special registers of the master machine */
		struct kvm_sregs sregs = *other->vcpu.cached_sregs;

		/* Page table entry will be cloned at the start */
		sregs.cr3 = memory.page_tables;
		sregs.cr0 &= ~CR0_WP;

		vcpu.set_special_registers(sregs);
		//print_pagetables(this->memory);
#if 0
		/* It shouldn't be identity-mapped anymore */
		assert(translate(IST_ADDR) != IST_ADDR);
		//printf("Translate 0x%lX => 0x%lX\n", IST_ADDR, translate(IST_ADDR));
		page_at(memory, IST_ADDR, [] (auto, auto& entry, auto) {
			assert(entry & (PDE64_PRESENT | PDE64_RW | PDE64_NX));
			(void) entry;
		});
#endif
	} else { /* Forked linearized VM */
		/* We have to re-initialize the page tables,
		   because the source machine has been CoW-prepped.
		   NOTE: Better solution is to replace CLONEABLE flags with W=2 */
		setup_amd64_paging(memory, m_binary);

		/* Inherit the special registers of the master machine */
		struct kvm_sregs sregs;
		other->vcpu.get_special_registers(sregs);

		/* Restore the original linearized memory */
		sregs.cr3 = memory.page_tables;
		sregs.cr0 |= CR0_WP;

		vcpu.set_special_registers(sregs);
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

#define PRINTER(printer, buffer, fmt, ...) \
	printer(buffer, \
		snprintf(buffer, sizeof(buffer), \
		fmt, ##__VA_ARGS__));

TINYKVM_COLD()
void Machine::print_registers()
{
	struct kvm_sregs sregs;
	vcpu.get_special_registers(sregs);

	char buffer[1024];
	PRINTER(m_printer, buffer,
		"CR0: 0x%llX  CR3: 0x%llX\n", sregs.cr0, sregs.cr3);
	PRINTER(m_printer, buffer,
		"CR2: 0x%llX  CR4: 0x%llX\n", sregs.cr2, sregs.cr4);

	auto regs = registers();
	PRINTER(m_printer, buffer,
		"RAX: 0x%llX  RBX: 0x%llX  RCX: 0x%llX\n", regs.rax, regs.rbx, regs.rcx);
	PRINTER(m_printer, buffer,
		"RDX: 0x%llX  RSI: 0x%llX  RDI: 0x%llX\n", regs.rdx, regs.rsi, regs.rdi);
	PRINTER(m_printer, buffer,
		"RIP: 0x%llX  RBP: 0x%llX  RSP: 0x%llX\n", regs.rip, regs.rbp, regs.rsp);

	PRINTER(m_printer, buffer,
		"SS: 0x%X  CS: 0x%X  DS: 0x%X  FS: 0x%X  GS: 0x%X\n",
		sregs.ss.selector, sregs.cs.selector, sregs.ds.selector, sregs.fs.selector, sregs.gs.selector);

#if 0
	print_pagetables(memory);
#endif
#if 0
	PRINTER(m_printer, buffer,
		"CR0 PE=%llu MP=%llu EM=%llu\n",
		sregs.cr0 & 1, (sregs.cr0 >> 1) & 1, (sregs.cr0 >> 2) & 1);
	PRINTER(m_printer, buffer,
		"CR4 OSFXSR=%llu OSXMMEXCPT=%llu OSXSAVE=%llu\n",
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
	char buffer[1024];
	// Page fault
	if (intr == 14) {
		struct kvm_sregs sregs;
		get_special_registers(sregs);
		PRINTER(m_printer, buffer,
			"*** %s on address 0x%llX\n",
			amd64_exception_name(intr), sregs.cr2);
		uint64_t code;
		unsafe_copy_from_guest(&code, regs.rsp+8,  8);
		PRINTER(m_printer, buffer,
			"Error code: 0x%lX (%s)\n", code,
			(code & 0x02) ? "memory write" : "memory read");
		if (code & 0x01) {
			PRINTER(m_printer, buffer,
				"* Protection violation\n");
		} else {
			PRINTER(m_printer, buffer,
				"* Page not present\n");
		}
		if (code & 0x02) {
			PRINTER(m_printer, buffer,
				"* Invalid write on page\n");
		}
		if (code & 0x04) {
			PRINTER(m_printer, buffer,
				"* CPL=3 Page fault\n");
		}
		if (code & 0x08) {
			PRINTER(m_printer, buffer,
				"* Page contains invalid bits\n");
		}
		if (code & 0x10) {
			PRINTER(m_printer, buffer,
				"* Instruction fetch failed (NX-bit was set)\n");
		}
	} else {
		PRINTER(m_printer, buffer,
			"*** CPU EXCEPTION: %s (code: %s)\n",
			amd64_exception_name(intr),
			amd64_exception_code(intr) ? "true" : "false");
	}
	this->print_registers();
	//print_pagetables(memory);
	const bool has_code = amd64_exception_code(intr);

	try {
		uint64_t off = (has_code) ? (regs.rsp+8) : (regs.rsp+0);
		if (intr == 14) off += 8;
		uint64_t rip, cs = 0x0, rsp, ss;
		try {
			unsafe_copy_from_guest(&rip, off+0,  8);
			unsafe_copy_from_guest(&cs,  off+8,  8);
			unsafe_copy_from_guest(&rsp, off+24, 8);
			unsafe_copy_from_guest(&ss,  off+32, 8);

			PRINTER(m_printer, buffer,
				"Failing RIP: 0x%lX\n", rip);
			PRINTER(m_printer, buffer,
				"Failing CS:  0x%lX\n", cs);
			PRINTER(m_printer, buffer,
				"Failing RSP: 0x%lX\n", rsp);
			PRINTER(m_printer, buffer,
				"Failing SS:  0x%lX\n", ss);
		} catch (...) {}

		/* General Protection Fault */
		if (has_code && intr == 13) {
			uint64_t code = 0x0;
			try {
				unsafe_copy_from_guest(&code,  regs.rsp, 8);
			} catch (...) {}
			if (code != 0x0) {
				PRINTER(m_printer, buffer,
					"Reason: Failing segment 0x%lX\n", code);
			} else if (cs & 0x3) {
				/* Best guess: Privileged instruction */
				PRINTER(m_printer, buffer,
					"Reason: Executing a privileged instruction\n");
			} else {
				/* Kernel GPFs should be exceedingly rare */
				PRINTER(m_printer, buffer,
					"Reason: Protection fault in kernel mode\n");
			}
		}
	} catch (...) {}
}

void Machine::run(unsigned fixme_timeout)
{
	/* XXX: Remember to set a timeout. */
	this->m_stopped = false;
	while(run_once());
}

long Machine::run_once()
{
	if (ioctl(vcpu.fd, KVM_RUN, 0) < 0) {
		/* NOTE: This is probably EINTR */
		machine_exception("KVM_RUN failed");
	}

	switch (vcpu.kvm_run->exit_reason) {
	case KVM_EXIT_HLT:
		machine_exception("Halt from kernel space", 5);

	case KVM_EXIT_DEBUG:
		return KVM_EXIT_DEBUG;

	case KVM_EXIT_FAIL_ENTRY:
		machine_exception("Failed to start guest! Misconfigured?", KVM_EXIT_FAIL_ENTRY);

	case KVM_EXIT_SHUTDOWN:
		machine_exception("Shutdown! Triple fault?", 32);

	case KVM_EXIT_IO:
		if (vcpu.kvm_run->io.direction == KVM_EXIT_IO_OUT) {
		if (vcpu.kvm_run->io.port == 0x0) {
			const char* data = ((char *)vcpu.kvm_run) + vcpu.kvm_run->io.data_offset;
			const uint32_t intr = *(uint32_t *)data;
			if (intr != 0xFFFF) {
				this->system_call(intr);
				if (this->m_stopped) return 0;
				return KVM_EXIT_IO;
			} else {
				this->m_stopped = true;
				return 0;
			}
		}
		else if (vcpu.kvm_run->io.port >= 0x80 && vcpu.kvm_run->io.port < 0x100) {
			auto intr = vcpu.kvm_run->io.port - 0x80;
			if (intr == 14)
			{
				auto regs = registers();
				const uint64_t addr = regs.rdi & ~(uint64_t) 0x8000000000000FFF;
#ifdef VERBOSE_PAGE_FAULTS
				char buffer[256];
				#define PV(val, off) \
					{ uint64_t value; unsafe_copy_from_guest(&value, regs.rsp + off, 8); \
					PRINTER(m_printer, buffer, "Value %s: 0x%lX\n", val, value); }
				try {
					PV("Origin SS",  48);
					PV("Origin RSP", 40);
					PV("Origin RFLAGS", 32);
					PV("Origin CS",  24);
					PV("Origin RIP", 16);
					PV("Error code", 8);
				} catch (...) {}
				PRINTER(m_printer, buffer,
					"*** %s on address 0x%lX (0x%llX)\n",
					amd64_exception_name(intr), addr, regs.rdi);
#endif
				/* Page fault handling */
				/* We should be in kernel mode, otherwise it's fishy! */
				if (UNLIKELY(regs.rip > 0x3000)) {
					machine_exception("Security violation", intr);
				}

				memory.get_writable_page(addr, false);
				return KVM_EXIT_IO;
			}
			else if (intr == 1) /* Debug trap */
			{
				m_on_breakpoint(*this);
				return KVM_EXIT_IO;
			}
			/* CPU Exception */
			this->handle_exception(intr);
			machine_exception(amd64_exception_name(intr), intr);
		} else {
			/* Custom Output handler */
			const char* data = ((char *)vcpu.kvm_run) + vcpu.kvm_run->io.data_offset;
			m_on_output(*this, vcpu.kvm_run->io.port, *(uint32_t *)data);
		}
		} else { // IN
			/* Custom Input handler */
			const char* data = ((char *)vcpu.kvm_run) + vcpu.kvm_run->io.data_offset;
			m_on_input(*this, vcpu.kvm_run->io.port, *(uint32_t *)data);
		}
		if (this->m_stopped) return 0;
		return KVM_EXIT_IO;

	case KVM_EXIT_MMIO: {
			char buffer[256];
			PRINTER(m_printer, buffer,
				"Unknown MMIO write at 0x%llX\n",
				vcpu.kvm_run->mmio.phys_addr);
			machine_exception("Invalid MMIO write");
		}
	case KVM_EXIT_INTERNAL_ERROR:
		machine_exception("KVM internal error");
	}
	char buffer[256];
	PRINTER(m_printer, buffer,
		"Unexpected exit reason %d\n", vcpu.kvm_run->exit_reason);
	machine_exception("Unexpected KVM exit reason",
		vcpu.kvm_run->exit_reason);
}

TINYKVM_COLD()
long Machine::step_one()
{
	struct kvm_guest_debug dbg;
	dbg.control = KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_SINGLESTEP;

	if (ioctl(vcpu.fd, KVM_SET_GUEST_DEBUG, &dbg) < 0) {
		machine_exception("KVM_RUN failed");
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
		machine_exception("KVM_RUN failed");
	}

	return run_once();
}

void Machine::prepare_copy_on_write()
{
	assert(this->m_prepped == false);
	this->m_prepped = true;
	/* Make each writable page read-only, causing page fault */
	foreach_page_makecow(this->memory);
	//print_pagetables(this->memory);
	/* Cache all the special registers, which we will use on forks */
	if (vcpu.cached_sregs == nullptr) {
		vcpu.cached_sregs = new kvm_sregs {};
	}
	get_special_registers(*vcpu.cached_sregs);
}

void Machine::print_pagetables() const {
	tinykvm::print_pagetables(this->memory);
}

Machine::address_t Machine::entry_address() const noexcept {
	return usercode_header().vm64_entry;
}
Machine::address_t Machine::exit_address() const noexcept {
	return usercode_header().vm64_rexit;
}

}
