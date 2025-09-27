#include "machine.hpp"
#include "amd64/idt.hpp"
#include "amd64/usercode.hpp"
#include "linux/threads.hpp"
#include "util/scoped_profiler.hpp"
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
	if (&remote != this->m_remote) {
		if (this->m_remote != nullptr) {
			this->delete_memory(1);
			this->memory.delete_foreign_mmap_ranges();
			this->memory.delete_foreign_banks();
		}
		// Install the remote memory in this machine
		this->install_memory(1, remote_vmem, false);
		this->memory.install_mmap_ranges(remote);
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

	// Finalize
	this->m_remote = &remote;
	remote.m_remote = this; // Mutual
	if constexpr (VERBOSE_REMOTE) {
		fprintf(stderr, "Remote connected: this VM %p remote VM %p (%s)\n",
			this, &remote, connect_now ? "just-in-time" : "setup");
	}
}
static void copy_callee_saved_registers(bool save_all, tinykvm_regs& dest, const tinykvm_regs& src)
{
	if (!save_all) {
		// Callee-saved registers: RBX, RBP, R12-R15 + arguments in RDI, RSI
		dest.rbx = src.rbx;
		dest.rdi = src.rdi;
		dest.rsi = src.rsi;
		dest.rsp = src.rsp;
		dest.rbp = src.rbp;
		dest.r12 = src.r12;
		dest.r13 = src.r13;
		dest.r14 = src.r14;
		dest.r15 = src.r15;
		dest.rip = src.rip;
	} else {
		// Copy all registers (slower, but simpler)
		dest = src;
	}
}
void Machine::ipre_remote_resume_now(bool save_all, std::function<void(Machine&)> before)
{
	if (!has_remote())
		throw MachineException("Remote not enabled. Did you call 'remote_connect()'?");
	if (is_remote_connected())
		throw MachineException("Remote already connected");
	ScopedProfiler<MachineProfiling::RemoteResume> prof(profiling());

	// 1. Make a copy of current register state
	tinykvm_regs saved_gprs;
	copy_callee_saved_registers(save_all, saved_gprs, this->registers());
	tinykvm_fpuregs saved_fprs;
	if (save_all)
		saved_fprs = this->fpu_registers();

	// 2. Connect to remote now
	const auto remote_fsbase = this->remote_activate_now();

	// 3. Copy remote registers into current state
	tinykvm::Machine& remote_vm = remote();
	copy_callee_saved_registers(save_all, this->registers(), remote_vm.registers());
	this->set_registers(this->registers()); // Set dirty bit
	if (save_all)
		this->set_fpu_registers(remote_vm.fpu_registers());

	// Call the before function if provided
	if (before)
		before(*this);

	try {
		// 4. Resume execution
		// Set RDI to our FSBASE for the remote VM
		this->registers().rdi = remote_fsbase;
		this->run(0.0f);
	} catch (const std::exception& e) {
		// If an exception occurred, disconnect and restore FSBASE
		const auto our_fsbase = this->remote_disconnect();
		auto& local_sprs = vcpu.get_special_registers();
		local_sprs.fs.base = our_fsbase;
		this->set_special_registers(local_sprs);
		// If we restore original registers, the exception
		// will lose the information about what happened.
		throw; // Rethrow
	}

	// 5. Disconnect from remote and store back registers
	copy_callee_saved_registers(save_all, remote_vm.registers(), this->registers());
	remote_vm.registers().rip += 2; // Skip over OUT instruction
	// XXX: Avoid this???
	remote_vm.cpu().get_special_registers().fs.base =
		this->get_special_registers().fs.base;
	// After disconnect, access is no longer serialized (don't touch remote anymore)
	const auto our_fsbase = this->remote_disconnect();
	if (our_fsbase == 0)
		throw std::runtime_error("ipre_resume_storage: Remote disconnect failed");

	// 6. When returning, restore original register state
	copy_callee_saved_registers(save_all, this->registers(), saved_gprs);
	this->registers().rip += 2; // Skip over OUT instruction
	if (save_all)
		this->set_fpu_registers(saved_fprs);
	this->prepare_vmresume(our_fsbase, true);
	vcpu.stopped = false;
}
void Machine::ipre_permanent_remote_resume_now(bool store_fsbase_rdi)
{
	if (!has_remote())
		throw MachineException("Remote not enabled. Did you call 'remote_connect()'?");
	if (is_remote_connected())
		throw MachineException("Remote already connected");
	ScopedProfiler<MachineProfiling::RemoteResume> prof(profiling());

	// There is a permanent connection back from the remote into this VM,
	// because while this VM should not be able to "always" access the remote,
	// the remote VM should always be able to access this VM. This mode is for
	// when each calling VM has a permanent connection to a select remote VM.

	if (store_fsbase_rdi) {
		// Set RDI to FSBASE for the remote VM
		// This is for compatibility with other remote methods that expect
		// the FSBASE to be passed in RDI.
		this->registers().rdi = this->get_special_registers().fs.base;
		this->set_registers(this->registers()); // Set dirty bit
	}

	const auto remote_cow_counter = remote().memory.cow_written_pages.size();

	if (this->m_remote_cow_counter != remote_cow_counter) {
		this->m_remote_cow_counter = remote_cow_counter;
		// New working memory pages have been created in the remote,
		// so we need to make sure we see the latest changes.
		this->remote_connect(*this->m_remote, true);
		for (auto& bank : remote().memory.banks)
		{
			const VirtualMem vmem = bank.to_vmem();
			if (this->memory.remote_bank_break < bank.addr) {
				this->memory.remote_bank_break = bank.addr;
				if constexpr (VERBOSE_REMOTE) {
					fprintf(stderr, "Permanent remote: mapped bank %u at 0x%lX-0x%lX\n",
						bank.idx, bank.addr, bank.addr + bank.size());
				}
				const unsigned new_idx = memory.allocate_region_idx();
				this->install_memory(new_idx, vmem, false);
				memory.foreign_banks.push_back(new_idx);
			}
		}
		this->prepare_vmresume(0, true); // Reload page tables
	}

	// Resume execution directly into remote VM
	// Our execution timeout will interrupt the remote VM if needed.
	this->run_in_usermode(0.0f);
	this->registers().rip += 2; // Skip over OUT instruction

	if (remote_cow_counter != remote().memory.cow_written_pages.size()) {
		// New working memory pages have been created in the caller,
		// so we need to make sure it sees the latest changes.
		printf("Permanent remote: caller created new CoW pages, updating\n");
		remote().registers().rip += 2; // Skip over OUT instruction
		remote().prepare_vmresume(0, true); // Reload page tables
	}
}
void Machine::remote_pfault_permanent_ipre(uint64_t return_stack, uint64_t return_address)
{
	if (!has_remote())
		throw MachineException("Remote not enabled. Did you call 'remote_connect()'?");
	if (is_remote_connected())
		throw MachineException("Remote already connected");

	ScopedProfiler<MachineProfiling::RemoteResume> prof(profiling());

	// There is a permanent connection back from the remote into this VM,
	// because while this VM should not be able to "always" access the remote,
	// the remote VM should always be able to access this VM. This mode is for
	// when each calling VM has a permanent connection to a select remote VM.

	auto& caller = remote();
	// Copy all registers (page fault handler may need them all)
	this->set_registers(caller.registers());
	// Find the clobbered RIP after IRETQ, set RFLAGS to something sane
	// The PF handler also pushed RAX and RDI
	auto& regs = this->registers();
	struct StackStuff {
		uint64_t rdi;
		uint64_t rax;
		uint64_t return_rip;
	} stack;
	caller.unsafe_copy_from_guest(&stack, regs.rsp + 8, sizeof(stack));
	regs.rax = stack.rax;
	regs.rdi = stack.rdi;
	/* Set IOPL=3 to allow I/O instructions in usermode */
	regs.rflags = 2 | (3 << 12);
	regs.rip = stack.return_rip;
	regs.rsp = return_stack;
	// Redirect the return address to our usercode entry
	const uint64_t leave_function = this->exit_address();
	this->copy_to_guest(regs.rsp, &leave_function, sizeof(leave_function));
	this->set_registers(regs); // Set dirty bit

	const auto remote_cow_counter = caller.memory.cow_written_pages.size();

	if (this->m_remote_cow_counter != remote_cow_counter) {
		this->m_remote_cow_counter = remote_cow_counter;
		// New working memory pages have been created in the remote,
		// so we need to make sure we see the latest changes.
		this->remote_connect(*this->m_remote, true);
		for (auto& bank : remote().memory.banks)
		{
			const VirtualMem vmem = bank.to_vmem();
			if (this->memory.remote_bank_break < bank.addr) {
				this->memory.remote_bank_break = bank.addr;
				if constexpr (VERBOSE_REMOTE) {
					fprintf(stderr, "Permanent remote pfault: mapped bank %u at 0x%lX-0x%lX\n",
						bank.idx, bank.addr, bank.addr + bank.size());
				}
				const unsigned new_idx = memory.allocate_region_idx();
				this->install_memory(new_idx, vmem, false);
				memory.foreign_banks.push_back(new_idx);
			}
		}
		this->prepare_vmresume(0, true); // Reload page tables
	}

	// Resume execution directly into remote VM
	// Our execution timeout will interrupt the remote VM if needed.
	this->run_in_usermode(0.0f);

	// Now we return to the caller, _forcing_ usermode exit
	caller.set_registers(this->registers());
	// Emulate RET from the caller
	caller.registers().rip = return_address;
	caller.registers().rsp += 8;
	caller.enter_usermode();
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
