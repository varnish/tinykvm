#include "smp.hpp"

#include "machine.hpp"
#include <cassert>
#include <linux/kvm.h>
#include <sys/ioctl.h>

namespace tinykvm {

SMP& Machine::smp() {
	if (m_smp == nullptr)
		m_smp.reset(new SMP(*this));
	return *m_smp;
}
const SMP& Machine::smp() const {
	if (m_smp == nullptr)
		m_smp.reset(new SMP(const_cast<Machine&> (*this)));
	return *m_smp;
}
bool Machine::smp_active() const noexcept {
	if (m_smp == nullptr) return false;
	return smp().smp_active() != 0;
}
int  Machine::smp_active_count() const noexcept {
	if (m_smp == nullptr) return 0;
	return smp().smp_active();
}
void Machine::smp_wait() {
	if (m_smp == nullptr)
		return;
	smp().wait();
}
void Machine::smp_vcpu_broadcast(std::function<void(vCPU&)> callback)
{
	if (m_smp == nullptr)
		return;
	smp().broadcast(std::move(callback));
}

SMP::~SMP()
{
	m_cpus.clear();
}


SMP::MPvCPU::MPvCPU(int c, Machine& m)
	: thpool(1, 0, false)
{
	/* We store the CPU ID in GSBASE register
	   XXX: We do not make sure that vCPUs stay on a specific
	   thread here, which will decimate performance. */
	auto f = thpool.enqueue([this, c, &m] {
		this->cpu.smp_init(c, m);
	});
}
SMP::MPvCPU::~MPvCPU() {}


void SMP::MPvCPU::blocking_message(std::function<void(vCPU&)> func)
{
	auto res = thpool.enqueue([this, func] {
		func(this->cpu);
	});
	res.get();
}

void SMP::MPvCPU::async_exec(MPvCPU_data& data)
{
	/* To get the best performance we do:
		1. Allocate regs on heap.
		2. Set regs and timeout in MP vCPU.
		3. Assign and delete regs at vCPU thread.
		4. Start the vCPU with timeout in vCPU (for SSO).

		This means it is *NOT* possible to schedule more than
		one execution at the same time due to regs race.
	*/
	thpool.enqueue([&data] {
		auto& vcpu = *data.vcpu;
		try {
			/*printf("Working from vCPU %d, RIP=0x%llX  RSP=0x%llX  ARG=0x%llX\n",
				cpu.cpu_id, regs->rip, regs->rsp, regs->rsi);*/
			vcpu.set_registers(data.regs);

			vcpu.run(data.ticks);
			vcpu.decrement_smp_count();

		} catch (const tinykvm::MemoryException& e) {
			printf("SMP memory exception: %s (addr=0x%lX, size=0x%lX)\n",
				e.what(), e.addr(), e.size());
			vcpu.decrement_smp_count();
			throw;
		} catch (const std::exception& e) {
			printf("SMP exception: %s\n", e.what());
			vcpu.decrement_smp_count();
			throw;
		}
	});
}

SMP::MPvCPU_data* SMP::smp_allocate_vcpu_data(size_t num_cpus)
{
	auto* data = new MPvCPU_data[num_cpus];

	std::lock_guard<std::mutex> lock(m_smp_data_mtx);
	m_smp_data.push_back(data);

	return data;
}
void SMP::prepare_cpus(size_t num_cpus)
{
	if (m_cpus.size() < num_cpus) {
		while (m_cpus.size() < num_cpus) {
			/* NB: The cpu ids start at 1..2..3.. */
			const int c = 1 + m_cpus.size();
			m_cpus.emplace_back(c, machine());
		}
		//printf("%zu SMP vCPUs initialized\n", this->m_cpus.size());
	}
}
void vCPU::decrement_smp_count()
{
	auto& smp = machine().smp();
	const int v = __sync_fetch_and_sub(&smp.m_smp_active, 1);
	/* Check if we are the lucky one to clear out the SMP registers. */
	if (UNLIKELY(v == 1))
	{
		/* Create temporary vector and swap in contents. */
		smp.m_smp_data_mtx.lock();
		auto tmp = std::move(smp.m_smp_data);
		smp.m_smp_data_mtx.unlock();
		/* Delete registers one by one, then let it destruct. */
		for (auto* regs : tmp)
			delete[] regs;
	}
}

void SMP::broadcast(std::function<void(vCPU &)> func)
{
	for (auto& cpu : this->m_cpus) {
		cpu.blocking_message(func);
	}
}

void SMP::timed_smpcall_array(size_t num_cpus,
	address_t stack_base, uint32_t stack_size,
	address_t addr, float timeout,
	address_t array, uint32_t array_isize)
{
	assert(num_cpus != 0);
	this->prepare_cpus(num_cpus);
	auto* data = smp_allocate_vcpu_data(num_cpus);

	__sync_fetch_and_add(&m_smp_active, num_cpus);

	for (size_t c = 0; c < m_cpus.size(); c++) {
		data[c].vcpu = &m_cpus[c].cpu;
		data[c].ticks = to_ticks(timeout);
		machine().setup_call(data[c].regs, addr,
			stack_base + (c+1) * stack_size,
			array + (c+1) * array_isize,
			array_isize);
		m_cpus[c].async_exec(data[c]);
	}
}

void SMP::timed_smpcall_clone(size_t num_cpus,
	address_t stack_base, uint32_t stack_size,
	float timeout, const tinykvm_x86regs& regs)
{
	assert(num_cpus != 0);
	this->prepare_cpus(num_cpus);
	auto* data = smp_allocate_vcpu_data(num_cpus);

	__sync_fetch_and_add(&m_smp_active, num_cpus);

	for (size_t c = 0; c < m_cpus.size(); c++) {
		data[c].vcpu = &m_cpus[c].cpu;
		data[c].ticks = to_ticks(timeout);
		data[c].regs = regs;
		machine().setup_clone(data[c].regs,
			stack_base + (c+1) * stack_size);

		m_cpus[c].async_exec(data[c]);
	}
}

void SMP::wait()
{
	for (size_t c = 0; c < m_cpus.size(); c++) {
		m_cpus[c].thpool.wait_until_nothing_in_flight();
	}
}

std::vector<long> SMP::gather_return_values(unsigned cpus)
{
	if (cpus == 0 || cpus > m_cpus.size())
		cpus = m_cpus.size();

	std::vector<long> results;
	results.resize(cpus);
	for (size_t c = 0; c < cpus; c++) {
		m_cpus[c].blocking_message([&] (auto& cpu) {
			//printf("CPU %zu result: 0x%llu\n", c, cpu.registers().rdi);
			results[c] = cpu.registers().rdi;
		});
	}
	return results;
}

}
