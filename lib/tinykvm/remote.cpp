#include "machine.hpp"

namespace tinykvm {

void Machine::remote_connect(Machine& remote)
{
	// Install the remote memory in this machine
	const auto remote_vmem = remote.main_memory().vmem();
	this->install_memory(1, remote_vmem, false);

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
		main_pdpt[i] = remote_pdpt[i]; // GB-page
	}

	// Finalize
	this->m_remote = &remote;
}

} // tinykvm
