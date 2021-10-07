#include "machine.hpp"
#include <cassert>
#include <linux/kvm.h>

namespace tinykvm {

Machine::MPvCPU::MPvCPU(int c, Machine& m, const struct kvm_sregs& sregs)
	: thpool(1)
{
	/* We store the CPU ID in GSBASE register */
	auto f = thpool.enqueue([this, c, &m, sregs = sregs] () mutable {
		this->cpu.smp_init(c, m);
		sregs.gs.base = c;
		sregs.gs.selector = c;
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
