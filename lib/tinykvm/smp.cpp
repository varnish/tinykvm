#include "machine.hpp"
#include "kernel/memory_layout.hpp"
#include "kernel/usercode.hpp"
#include <cassert>
#include <linux/kvm.h>
#include <sys/ioctl.h>

namespace tinykvm {

Machine::MPvCPU::MPvCPU(int c, Machine& m, const struct kvm_sregs& sregs)
	: thpool(1)
{
	/* We store the CPU ID in GSBASE register */
	auto f = thpool.enqueue([this, c, &m, sregs = sregs] () mutable {
		this->cpu.smp_init(c, m);
		sregs.tr.base = TSS_SMP_ADDR + (c - 1) * 104; /* AMD64_TSS */
		sregs.gs.base = usercode_header().vm64_cpuid + 4 * c;
		this->cpu.set_special_registers(sregs);
	});
}
Machine::MPvCPU::~MPvCPU() {}

void Machine::MPvCPU::blocking_message(std::function<void(vCPU&)> func)
{
	auto res = thpool.enqueue([this, func] {
		func(this->cpu);
	});
	res.get();
}

void Machine::MPvCPU::async_exec(const struct tinykvm_x86regs* regs, uint32_t ticks)
{
	/* To get the best performance we do:
		1. Allocate regs on heap.
		2. Set regs and timeout in MP vCPU.
		3. Assign and delete regs at vCPU thread.
		4. Start the vCPU with timeout in vCPU (for SSO).

		This means it is *NOT* possible to schedule more than
		one execution at the same time due to regs race.
	*/
	this->regs = regs;
	this->ticks = ticks;
	thpool.enqueue([this] {
		try {
			/* XXX: This really necessary? Keep it? */
			auto* regs = this->regs;
			this->regs = nullptr;
			/*printf("Working from vCPU %d, RIP=0x%llX  RSP=0x%llX  ARG=0x%llX\n",
				cpu.cpu_id, regs->rip, regs->rsp, regs->rsi);*/
			cpu.assign_registers(*regs);
			delete regs;

			cpu.run(this->ticks);
			cpu.decrement_smp_count();

		} catch (const tinykvm::MemoryException& e) {
			printf("SMP memory exception: %s (addr=0x%lX, size=0x%lX)\n",
				e.what(), e.addr(), e.size());
			cpu.decrement_smp_count();
			throw;
		} catch (const std::exception& e) {
			printf("SMP exception: %s\n", e.what());
			cpu.decrement_smp_count();
			throw;
		}
	});
}

void Machine::prepare_cpus(size_t num_cpus)
{
	if (m_cpus.size() < num_cpus) {
		/* Inherit the special registers of the main vCPU */
		struct kvm_sregs sregs;
		vcpu.get_special_registers(sregs);

		while (m_cpus.size() < num_cpus) {
			/* NB: The cpu ids start at 1..2..3.. */
			const int c = 1 + m_cpus.size();
			m_cpus.emplace_back(c, *this, sregs);
		}
		//printf("%zu SMP vCPUs initialized\n", this->m_cpus.size());
	}
}

void Machine::timed_smpcall_array(size_t num_cpus,
	address_t stack_base, uint32_t stack_size,
	address_t addr, float timeout,
	address_t array, uint32_t array_isize)
{
	assert(num_cpus != 0);
	this->prepare_cpus(num_cpus);
	__sync_fetch_and_add(&m_smp_active, num_cpus);

	for (size_t c = 0; c < m_cpus.size(); c++) {
		auto regs = new tinykvm_x86regs;
		this->setup_call(*regs, addr,
			stack_base + (c+1) * stack_size,
			array + (c+1) * array_isize,
			array_isize);
		m_cpus[c].async_exec(regs, to_ticks(timeout));
	}
}

void Machine::timed_smpcall_clone(size_t num_cpus,
	address_t stack_base, uint32_t stack_size,
	float timeout, const tinykvm_x86regs& regs)
{
	assert(num_cpus != 0);
	this->prepare_cpus(num_cpus);
	__sync_fetch_and_add(&m_smp_active, num_cpus);

	for (size_t c = 0; c < m_cpus.size(); c++) {
		auto new_regs = new tinykvm_x86regs {regs};
		this->setup_clone(*new_regs,
			stack_base + (c+1) * stack_size);

		m_cpus[c].async_exec(new_regs, to_ticks(timeout));
	}
}

void Machine::smp_wait()
{
	for (size_t c = 0; c < m_cpus.size(); c++) {
		m_cpus[c].thpool.wait_until_nothing_in_flight();
	}
}

std::vector<long> Machine::gather_return_values()
{
	std::vector<long> results;
	results.resize(this->m_cpus.size());
	for (size_t c = 0; c < m_cpus.size(); c++) {
		m_cpus[c].blocking_message([&] (auto& cpu) {
			//printf("CPU %zu result: 0x%llu\n", c, cpu.registers().rdi);
			results[c] = cpu.registers().rdi;
		});
	}
	return results;
}

}
