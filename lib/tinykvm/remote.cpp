#include "machine.hpp"

#include "amd64/usercode.hpp"
#include <linux/kvm.h>

namespace tinykvm {

Machine& Machine::remote()
{
	if (this->is_remote_connected())
		return *m_remote;
	throw MachineException("Remote not enabled");
}
const Machine& Machine::remote() const
{
	if (this->is_remote_connected())
		return *m_remote;
	throw MachineException("Remote not enabled");
}

void Machine::remote_memory_mapping(Machine& remote, bool enabled)
{
	const auto remote_vmem = remote.main_memory().vmem();

	// Copy gigabyte pages covered by remote memory into these page tables
	static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
	auto* main_pml4 = this->main_memory().page_at(this->main_memory().page_tables);
	auto* main_pdpt = this->main_memory().page_at(main_pml4[0] & PDE64_ADDR_MASK);

	auto* remote_pml4 = remote.main_memory().page_at(remote.main_memory().page_tables);
	auto* remote_pdpt = remote.main_memory().page_at(remote_pml4[0] & PDE64_ADDR_MASK);

	// Gigabyte starting index and end index (rounded up)
	const auto begin = remote_vmem.physbase >> 30;
	const auto end   = (remote_vmem.physbase + remote_vmem.size + 0x3FFFFFFF) >> 30;

	// Install gigabyte entries from remote VM into this VM
	// The VM and page tables technically support 2MB region alignments.
	for (size_t i = begin; i < end; i++)
	{
		main_pdpt[i] = (enabled) ? remote_pdpt[i] : 0x0;
	}
}

void Machine::remote_connect(Machine& remote, bool pagetable_mapping)
{
	// Install the remote memory in this machine
	const auto remote_vmem = remote.main_memory().vmem();
	this->install_memory(1, remote_vmem, false);

	if (pagetable_mapping) {
		/* With the mapping always present we never want to trap. */
		this->remote_memory_mapping(remote, true);
		this->m_remote_base_address = UINT64_MAX;
	}
	else {
		/* Enable trapping on addresses >= remote base address. */
		this->m_remote_base_address = remote_vmem.physbase;
	}

	// Finalize
	this->m_remote = &remote;
}

void vCPU::handle_remote_call(uint64_t addr)
{
	auto& regs = this->registers();
	const auto old_regs = regs;
	auto& sregs = this->get_special_registers();
	const auto old_sregs = sregs;
	auto& remote = machine().remote();

	/* Exception frame RSP and RFLAGS */
	uint64_t& guest_rsp =
		*(uint64_t *)machine().main_memory().at(regs.rsp + 40); /* RSP */
	const uint64_t guest_rflags =
		*(uint64_t *)machine().main_memory().at(regs.rsp + 32); /* RFLAGS */
	uint64_t& guest_rip =
		*(uint64_t *)machine().main_memory().at(regs.rsp + 16); /* RIP */
	const uint64_t guest_cs =
		*(uint64_t *)machine().main_memory().at(regs.rsp + 24); /* CS */
	uint64_t guest_return = 0x0;
	printf("Local RSP: 0x%lX  rflags: 0x%lX\n", guest_rsp, guest_rflags);
	printf("Local RIP: 0x%lX  vs addr: 0x%lX\n", guest_rip, addr);
	printf("Local CS: 0x%lX\n", guest_cs);

	if (guest_rsp % 8 != 0)
		throw MachineException("Invalid stack alignment during remote jump", guest_rsp);

	guest_return =
		*(uint64_t *)machine().main_memory().safely_at(guest_rsp, 8); /* RA */
	printf("Guest return address: 0x%lX\n", guest_return);

	/* Temporarily map in the remote gigapages */
	machine().remote_memory_mapping(remote, true);

	try {
		/* VM call on remote memory */
		regs.rsp = guest_rsp;
		regs.rip = addr;
		regs.rflags = guest_rflags;
		/* Temporarily set new FS base */
		//sregs.fs.base = remote.get_special_registers().fs.base;
		sregs = remote.get_special_registers();
		sregs.cs.selector = 0x2B;
		sregs.ss.selector = 0x23;
		/* Complete faulting instruction */
		machine().step_one();
		machine().step_one();

		printf("New RIP: 0x%llX\n", regs.rip);
		printf("New RSP: 0x%llX\n", regs.rsp);

		guest_return =
			*(uint64_t *)machine().main_memory().safely_at(regs.rsp, 8); /* RA */
		printf("Guest return address: 0x%lX\n", guest_return);

		printf(">>> Running remote code\n");
		this->run_once();
		printf(">>> Completed running\n");
		if (this->stopped == false)
			throw MachineException("Remote VM call did not stop correctly");
		this->stopped = false;
		printf("Stopped correctly, returning to caller\n");

	} catch (const MachineException& me) {
		/* Restore all registers */
		sregs = old_sregs;
		regs.rip = old_regs.rip;
		regs.rsp = old_regs.rsp;
		regs.rflags = old_regs.rflags;
		/* Unmap the remote pages */
		machine().remote_memory_mapping(remote, false);
		throw;
	}

	/* Restore registers */
	sregs = old_sregs;
	regs.rip = old_regs.rip;
	regs.rsp = old_regs.rsp;
	regs.rflags = old_regs.rflags;
	/* Simulate return */
	guest_rip = guest_return;
	guest_rsp += 0x8;
	/* Unmap the remote pages */
	machine().remote_memory_mapping(remote, false);
}

} // tinykvm
