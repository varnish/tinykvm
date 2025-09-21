#include "machine.hpp"
#include "amd64/idt.hpp"
#include "amd64/usercode.hpp"
#include "linux/threads.hpp"
#include <linux/kvm.h>
#include <thread>

namespace tinykvm {
static constexpr bool VERBOSE_REMOTE = false;

Machine& Machine::remote()
{
	if (this->has_remote())
		return *m_remote;
	throw MachineException("Remote not enabled");
}
const Machine& Machine::remote() const
{
	if (this->has_remote())
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

	if (connect_now)
	{
		// Copy gigabyte entries covered by remote memory into these page tables
		static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
		auto* main_pml4 = this->main_memory().page_at(this->main_memory().page_tables);
		auto* main_pdpt = this->main_memory().page_at(main_pml4[0] & PDE64_ADDR_MASK);

		auto* remote_pml4 = remote.main_memory().page_at(remote.main_memory().page_tables);
		auto* remote_pdpt = remote.main_memory().page_at(remote_pml4[0] & PDE64_ADDR_MASK);

		// Gigabyte starting index and end index (rounded up)
		const auto begin = remote_vmem.physbase >> 30;
		const auto end   = (remote_vmem.remote_end + 0x3FFFFFFF) >> 30;
		if (UNLIKELY(begin >= 512 || end > 512 || begin >= end))
			throw MachineException("Remote memory produced invalid indexes (>512GB?)");

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
		hdr.vm64_remote_return_addr =
			usercode_header().translated_vm_remote_disconnect(this->main_memory());
	}

	// Finalize
	this->m_remote = &remote;
	if constexpr (VERBOSE_REMOTE) {
		fprintf(stderr, "Remote connected: this VM %p remote VM %p (%s)\n",
			this, &remote, connect_now ? "just-in-time" : "setup");
	}
}
void Machine::ipre_remote_resume_now(float timeout, bool save_fpu)
{
	if (!has_remote())
		throw MachineException("Remote not enabled. Did you call 'remote_connect()'?");
	if (is_remote_connected())
		throw MachineException("Remote already connected");
	tinykvm::Machine& remote_vm = remote();
	// 1. Connect to remote now
	const auto remote_fsbase = this->remote_activate_now();

	// 2. Make a copy of current register state
	auto saved_gprs = this->registers();
	tinykvm_fpuregs saved_fprs;
	if (save_fpu)
		saved_fprs = this->fpu_registers();
	auto& local_sprs = cpu().get_special_registers();
	auto& callee_sprs = remote_vm.get_special_registers();

	// 3. Copy remote registers into current state
	this->set_registers(remote_vm.registers());
	if (save_fpu)
		this->set_fpu_registers(remote_vm.fpu_registers());
	local_sprs.fs.base = remote_fsbase;
	this->set_special_registers(local_sprs);

	try {
		// 4. Resume execution
		this->vmresume(timeout);
	} catch (const std::exception& e) {
		// If an exception occurred, disconnect and
		// restore FSBASE
		const auto our_fsbase = this->remote_disconnect();
		local_sprs.fs.base = our_fsbase;
		this->set_special_registers(local_sprs);
		// If we restore original registers, the exception
		// will lose the information about what happened.
		throw; // Rethrow
	}

	// 5. Disconnect from remote and reset waiting state
	const auto our_fsbase = this->remote_disconnect();
	if (our_fsbase == 0)
		throw std::runtime_error("ipre_resume_storage: Remote disconnect failed");

	// 5. Skip over OUT instruction in original registers
	saved_gprs.rip += 2;

	// 6. When returning, restore original register state
	this->set_registers(saved_gprs);
	if (save_fpu)
		this->set_fpu_registers(saved_fprs);
	local_sprs.fs.base = our_fsbase;
	this->set_special_registers(local_sprs);
	this->prepare_vmresume();
	vcpu.stopped = false;
}

Machine::address_t Machine::remote_activate_now()
{
	if (this->m_remote == nullptr)
		throw MachineException("Remote not enabled");

	this->remote_connect(*this->m_remote, true);
	this->m_remote_connections++;

	// Set current FSBASE to remote original FSBASE
	vcpu.remote_original_tls_base = get_fsgs().first;

	auto& remote = *this->m_remote;
	if (remote.cpu().remote_serializer != nullptr)
	{
		// Use the remote serializer for this vCPU
		remote.cpu().remote_serializer->lock();
		if constexpr (VERBOSE_REMOTE) {
			fprintf(stderr, "Remote has serialized access: this VM %p remote VM %p\n",
				this, this->m_remote);
		}
	}
	else if constexpr (false)
	{
		const int this_cpuid = this->vcpu.cpu_id;
		if (remote.has_threads() && this_cpuid > 0 && remote.threads().size() > 1) {
			// So, the idea here is to just pick a thread if there are enough
			// threads to cover all possible vCPU IDs. This is a bit hacky, and
			// ideally we'd like to have a list of self-assigned threads dedicated
			// for the purpose of acting as "thread local" for each callee during
			// a remote call. For now, counter-based selection should "work".
			auto& threads = remote.threads().threads();
			auto it = threads.begin();
			for (int i = 0; i < this_cpuid && i < (int)threads.size(); i++, ++it);
			if constexpr (VERBOSE_REMOTE) {
				fprintf(stderr, "Remote activated on thread %d for vCPU %d\n", it->first, this_cpuid);
			}
			return it->second.fsbase;
		}
	}
	remote.m_remote = this; // Set halfway state
	// Set the vCPU machine to the remote machine
	this->vcpu.set_original_machine(this);
	this->vcpu.set_machine(&remote);
	// Return FSBASE of remote, which can be set more efficiently
	// in the mini-kernel assembly
	return remote.get_fsgs().first;
}
Machine::address_t Machine::remote_disconnect()
{
	if (!this->is_remote_connected())
		return 0;

	auto& remote = *this->m_remote;
	remote.m_remote = nullptr; // Clear halfway state
	if (remote.cpu().remote_serializer != nullptr)
	{
		// Unlock the remote serializer
		remote.cpu().remote_serializer->unlock();
		if constexpr (VERBOSE_REMOTE) {
			fprintf(stderr, "Remote serializer unlocked: this VM %p remote VM %p\n", this, this->m_remote);
		}
	}

	// Restore the vCPU machine to the original machine
	this->vcpu.set_machine(this->vcpu.original_machine());

	// Unpresent gigabyte entries from remote VM in this VM
	const auto remote_vmem = remote.main_memory().vmem();
	static constexpr uint64_t PDE64_ADDR_MASK = ~0x8000000000000FFF;
	auto* main_pml4 = this->main_memory().page_at(this->main_memory().page_tables);
	auto* main_pdpt = this->main_memory().page_at(main_pml4[0] & PDE64_ADDR_MASK);

	// Gigabyte starting index and end index (rounded up)
	const auto begin = remote_vmem.physbase >> 30;
	const auto end   = (remote_vmem.remote_end + 0x3FFFFFFF) >> 30;

	for (size_t i = begin; i < end; i++)
	{
		main_pdpt[i] = 0; // Clear entry
	}

	// Restore original FSBASE
	auto tls_base = this->vcpu.remote_original_tls_base;
	this->vcpu.remote_original_tls_base = 0;
	if constexpr (VERBOSE_REMOTE) {
		fprintf(stderr, "Remote disconnected, TLS base restored to 0x%lX: this VM %p remote VM %p\n",
			tls_base, this, this->m_remote);
	}
	return tls_base;
}
bool Machine::is_remote_connected() const noexcept
{
	return this->m_remote != nullptr && this->vcpu.remote_original_tls_base != 0;
}

bool Machine::is_foreign_address(address_t addr) const noexcept
{
	if (this->has_remote()) {
		const auto& rmem = this->m_remote->main_memory();
		bool test = addr >= rmem.physbase && addr < rmem.remote_end;
		if constexpr (VERBOSE_REMOTE) {
			printf("Address 0x%lX is in remote memory 0x%lX-0x%lX? %s\n",
				addr, rmem.physbase, rmem.remote_end, test ? "yes" : "no");
		}
		return test;
	}
	return false;
}

} // tinykvm
