#include "machine.hpp"
#include "amd64/idt.hpp"
#include "amd64/usercode.hpp"

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

void Machine::remote_connect(Machine& remote, bool connect_now)
{
	const auto remote_vmem = remote.main_memory().vmem();
	if (this->m_remote == nullptr) {
		// Install the remote memory in this machine
		this->install_memory(1, remote_vmem, false);
	} else if (&remote != this->m_remote) {
		throw MachineException("Remote already connected to another VM");
	}

	// Copy gigabyte pages covered by remote memory into these page tables
	static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
	auto* main_pml4 = this->main_memory().page_at(this->main_memory().page_tables);
	auto* main_pdpt = this->main_memory().page_at(main_pml4[0] & PDE64_ADDR_MASK);

	auto* remote_pml4 = remote.main_memory().page_at(remote.main_memory().page_tables);
	auto* remote_pdpt = remote.main_memory().page_at(remote_pml4[0] & PDE64_ADDR_MASK);

	// Gigabyte starting index and end index (rounded up)
	const auto begin = remote_vmem.physbase >> 30;
	const auto end   = (remote_vmem.physbase + remote_vmem.size + 0x3FFFFFFF) >> 30;

	if (connect_now)
	{
		// Install gigabyte entries from remote VM into this VM
		// The VM and page tables technically support 2MB region alignments.
		for (size_t i = begin; i < end; i++)
		{
			main_pdpt[i] = remote_pdpt[i]; // GB-page
		}
	}
	else
	{
		// Live-patch the interrupt assembly to support remote memory
		uint64_t* iasm = memory.page_at(memory.physbase + INTR_ASM_ADDR);
		iasm_header& hdr = *(iasm_header*)iasm;
		hdr.vm64_remote_base = remote_vmem.physbase;
		hdr.vm64_remote_return_addr =
			usercode_header().translated_vm_remote_disconnect(this->main_memory());
	}

	// Finalize
	this->m_remote = &remote;
}

Machine::address_t Machine::remote_activate_now()
{
	this->remote_connect(*this->m_remote, true);

	// Set current FSBASE to remote FSBASE
	vcpu.remote_original_tls_base = get_fsgs().first;

	// Return FSBASE of remote, which can be set more efficiently
	// in the mini-kernel assembly
	return this->m_remote->get_fsgs().first;
}
Machine::address_t Machine::remote_disconnect()
{
	if (this->m_remote == nullptr)
		return 0;

	// Unpresent gigabyte entries from remote VM in this VM
	const auto remote_vmem = this->m_remote->main_memory().vmem();
	static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
	auto* main_pml4 = this->main_memory().page_at(this->main_memory().page_tables);
	auto* main_pdpt = this->main_memory().page_at(main_pml4[0] & PDE64_ADDR_MASK);

	// Gigabyte starting index and end index (rounded up)
	const auto begin = remote_vmem.physbase >> 30;
	const auto end   = (remote_vmem.physbase + remote_vmem.size + 0x3FFFFFFF) >> 30;

	for (size_t i = begin; i < end; i++)
	{
		main_pdpt[i] = 0; // Clear entry
	}

	// Restore original FSBASE
	auto result = vcpu.remote_original_tls_base;
	vcpu.remote_original_tls_base = 0;
	return result;
}


Machine::address_t Machine::remote_base_address() const noexcept
{
	if (this->is_remote_connected())
		return this->m_remote->main_memory().physbase;
	return 0;
}

} // tinykvm
