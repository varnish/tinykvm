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

void Machine::MPvCPU::async_exec(const struct tinykvm_x86regs& regs, float timeout)
{
	/* To get the best performance we do:
		1. Compact the first message into a stack struct pointer,
		to force the lambda capture small size optimization. The
		message contains a reference to the 144-byte register struct.
		2. Set regs async, but keep the future.
		3. Start the vCPU with timeout in vCPU (for SSO).
		4. Get the future to ensure the stack objects don't expire.

		This should theoretically maximize performance.
	*/
	struct FirstCall {
		const struct tinykvm_x86regs& regs;
		vCPU& cpu;
	};
	FirstCall firstcall { .regs = regs, .cpu = this->cpu };
	auto fut = thpool.enqueue([f = &firstcall] {
		f->cpu.assign_registers(f->regs);
	});

	this->timeout = timeout;
	thpool.enqueue([this] {
		try {
			/*printf("Working from vCPU %d, RIP=0x%llX  RSP=0x%llX  ARG=0x%llX\n",
				cpu.cpu_id, regs.rip, regs.rsp, regs.rsi);*/
			cpu.run(this->timeout);
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

	/* Wait for the regs to get assigned. */
	fut.get();
}

void Machine::prepare_cpus(size_t num_cpus)
{
	if (m_cpus == nullptr) {
		auto* array = (MPvCPU*) std::malloc(sizeof(MPvCPU) * num_cpus);
		/* Inherit the special registers of the main vCPU */
		struct kvm_sregs sregs;
		vcpu.get_special_registers(sregs);

		for (size_t c = 0; c < num_cpus; c++) {
			/* NB: The cpu ids start at 1..2..3.. */
			new (&array[c]) MPvCPU(1 + c, *this, sregs);
		}
		this->m_cpus = array;
		this->m_cpucount = num_cpus;
		//printf("%zu SMP vCPUs initialized\n", this->m_cpucount);
	}
	if (this->m_cpucount < num_cpus) {
		machine_exception("SMP vCPU count mismatch", num_cpus);
	}
}

void Machine::smp_wait() const
{
	for (size_t c = 0; c < m_cpucount; c++) {
		m_cpus[c].thpool.wait_until_nothing_in_flight();
	}
}

std::vector<long> Machine::gather_return_values() const
{
	std::vector<long> results;
	results.resize(this->m_cpucount);
	for (size_t c = 0; c < m_cpucount; c++) {
		m_cpus[c].blocking_message([&] (auto& cpu) {
			//printf("CPU %zu result: 0x%llu\n", c, cpu.registers().rdi);
			results[c] = cpu.registers().rdi;
		});
	}
	return results;
}

}
