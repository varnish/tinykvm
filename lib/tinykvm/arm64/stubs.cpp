#include "../machine.hpp"
#include "../linux/threads.hpp"
#include "../smp.hpp"

namespace tinykvm {

bool Machine::load_snapshot_state()
{
	return false;
}

bool vMemory::has_loadable_snapshot_state() const noexcept
{
	return false;
}

void* vMemory::get_snapshot_state_area() const
{
	return nullptr;
}

void Machine::save_snapshot_state_now(const std::vector<std::pair<uint64_t, uint64_t>>&) const
{
	throw MachineException("Snapshot CPU state is not implemented on ARM64");
}

void* Machine::get_snapshot_state_user_area() const
{
	return nullptr;
}

Machine& Machine::remote()
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

const Machine& Machine::remote() const
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::permanent_remote_connect(Machine&)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::remote_update_gigapage_mappings(Machine&, bool)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::remote_connect(Machine&, bool)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::ipre_remote_resume_now(bool, std::function<void(Machine&)>)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::ipre_permanent_remote_resume_now(bool)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

void Machine::remote_pfault_permanent_ipre(uint64_t, uint64_t)
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

Machine::address_t Machine::remote_activate_now()
{
	throw MachineException("Remote VM support is not implemented on ARM64");
}

Machine::address_t Machine::remote_disconnect()
{
	return 0;
}

bool Machine::is_remote_connected() const noexcept
{
	return false;
}

bool Machine::is_foreign_address(address_t) const noexcept
{
	return false;
}

SMP& Machine::smp()
{
	throw MachineException("SMP is not implemented on ARM64");
}

const SMP& Machine::smp() const
{
	throw MachineException("SMP is not implemented on ARM64");
}

bool Machine::smp_active() const noexcept
{
	return false;
}

int Machine::smp_active_count() const noexcept
{
	return 0;
}

void Machine::smp_wait()
{
}

void Machine::smp_vcpu_broadcast(std::function<void(vCPU&)>)
{
}

SMP::~SMP() = default;

SMP::MPvCPU::MPvCPU(int, Machine&)
	: thpool(0, 0, false)
{
	throw MachineException("SMP is not implemented on ARM64");
}

SMP::MPvCPU::~MPvCPU() = default;

void SMP::MPvCPU::blocking_message(std::function<void(vCPU&)>)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::MPvCPU::async_exec(MPvCPU_data&)
{
	throw MachineException("SMP is not implemented on ARM64");
}

SMP::MPvCPU_data* SMP::smp_allocate_vcpu_data(size_t)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::prepare_cpus(size_t)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::broadcast(std::function<void(vCPU&)>)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::timed_smpcall_array(size_t, address_t, uint32_t, address_t, float, address_t, uint32_t)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::timed_smpcall_clone(size_t, address_t, uint32_t, float, const tinykvm_regs&)
{
	throw MachineException("SMP is not implemented on ARM64");
}

void SMP::wait()
{
}

std::vector<long> SMP::gather_return_values(unsigned)
{
	return {};
}

Thread::Thread(MultiThreading& mtr, int t, uint64_t, uint64_t)
	: mt(mtr), tid(t)
{
}

Thread::Thread(MultiThreading& mtr, const Thread& other)
	: mt(mtr), tid(other.tid), stored_regs(other.stored_regs),
	  fsbase(other.fsbase), clear_tid(other.clear_tid)
{
}

void Thread::suspend(uint64_t)
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

tinykvm_regs Thread::activate()
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

void Thread::resume()
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

void Thread::exit()
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

MultiThreading::MultiThreading(Machine& m) : machine(m)
{
}

void MultiThreading::reset_to(const MultiThreading&)
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

void MultiThreading::set_to_and_suspend_others(int)
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

Thread& MultiThreading::get_thread()
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

Thread* MultiThreading::get_thread(int)
{
	return nullptr;
}

Thread& MultiThreading::create(int)
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

Thread& MultiThreading::create(int, uint64_t, uint64_t, uint64_t, uint64_t)
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

bool MultiThreading::suspend_and_yield(int64_t)
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

void MultiThreading::erase_thread(int)
{
}

void MultiThreading::wakeup_next()
{
}

const MultiThreading& Machine::threads() const
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

MultiThreading& Machine::threads()
{
	throw MachineException("Guest threading is not implemented on ARM64");
}

void Machine::setup_multithreading()
{
	/* Syscall table installation must succeed on ARM64; actual guest thread
	   operations still throw from the stubs above if reached. */
}

Signals::Signals() = default;
Signals::~Signals() = default;

SignalAction& Signals::get(int sig)
{
	return signals.at(sig);
}

void Signals::enter(vCPU&, int)
{
	throw MachineException("Guest signals are not implemented on ARM64");
}

SignalAction& Machine::sigaction(int sig)
{
	return signals().get(sig);
}

void Machine::print_remote_gdb_backtrace(const std::string&, const RemoteGDBOptions&)
{
	throw MachineException("Remote GDB support is not implemented on ARM64");
}

} // namespace tinykvm
