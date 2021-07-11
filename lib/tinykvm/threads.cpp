#include "threads.hpp"

#include "machine.hpp"
#include <linux/kvm.h>
#include <linux/futex.h>
#include <cassert>
#include <stdexcept>
//#define DEBUG_THREADS

#ifdef DEBUG_THREADS
#define THPRINT(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__);
#else
#define THPRINT(fmt, ...) /* fmt */
#endif

namespace tinykvm {

Thread::Thread(MultiThreading& mtr, int t, uint64_t tls, uint64_t stack)
	: mt(mtr), tid(t)
{
	this->fsbase = tls;
	this->stored_regs.rsp = stack;
}

void Thread::suspend(uint64_t return_value)
{
	// GPRs
	stored_regs = mt.machine.registers();
	stored_regs.rax = return_value;
	// thread pointer
	struct kvm_sregs sregs;
	mt.machine.get_special_registers(sregs);
	fsbase = sregs.fs.base;
	// add to suspended (NB: can throw)
	mt.m_suspended.push_back(this);
}
struct tinykvm_x86regs Thread::activate()
{
	mt.m_current = this;
	// thread pointer
	mt.machine.set_tls_base(this->fsbase);
	// return modified GPRs
	auto regs = mt.machine.registers();
	regs.rsp = this->stored_regs.rsp;
	return regs;
}
void Thread::resume()
{
	mt.m_current = this;
	// restore registers
	mt.machine.set_registers(this->stored_regs);
	mt.machine.set_tls_base(this->fsbase);
	THPRINT("Returning to tid=%d tls=0x%lX stack=0x%llX\n",
			this->tid, this->fsbase, this->stored_regs.rsp);
}
void Thread::exit()
{
	const bool exiting_myself = (mt.get_thread().tid == this->tid);
	// CLONE_CHILD_CLEARTID: set userspace TID value to zero
	if (this->clear_tid) {
		THPRINT("Clearing thread value for tid=%d at 0x%lX\n",
				this->tid, this->clear_tid);
		*(uint32_t*) mt.machine.rw_memory_at(this->clear_tid, 4) = 0;
	}
	auto& thr = this->mt;
	// delete this thread
	thr.erase_thread(this->tid);

	if (exiting_myself)
	{
		// resume next thread in suspended list
		thr.wakeup_next();
	}
}

MultiThreading::MultiThreading(Machine& m)
	: machine(m), main_thread(*this, 0, 0x0, 0x0)
{
	m_current = &main_thread;
}

Thread& MultiThreading::get_thread()
{
	return *m_current;
}
Thread* MultiThreading::get_thread(int tid) /* or nullptr */
{
	auto it = m_threads.find(tid);
	if (it == m_threads.end()) return nullptr;
	return &it->second;
}

Thread& MultiThreading::create(
	int flags, uint64_t ctid, uint64_t ptid, uint64_t stack, uint64_t tls)
{
	const int tid = ++this->thread_counter;
	auto it = m_threads.try_emplace(tid, *this, tid, tls, stack);
	Thread& thread = it.first->second;

	if (flags & CLONE_SETTLS) {
		THPRINT("CLONE_SETTLS 0x%lX\n", tls);
	}
	if (flags & CLONE_CHILD_SETTID) {
		THPRINT("CHILD_SETTID at 0x%lX\n", ctid);
		*(uint32_t*) machine.rw_memory_at(ctid, 4) = tid;
	}
	if (flags & CLONE_PARENT_SETTID) {
		THPRINT("PARENT_SETTID at 0x%lX\n", ptid);
		*(uint32_t*) machine.rw_memory_at(ptid, 4) = tid;
	}
	if (flags & CLONE_CHILD_CLEARTID) {
		THPRINT("CHILD_CLEARTID at 0x%lX\n", ctid);
		thread.clear_tid = ctid;
	}

	return thread;
}
bool MultiThreading::suspend_and_yield()
{
	auto& thread = get_thread();
	// don't go through the ardous yielding process when alone
	if (m_suspended.empty()) {
		return false;
	}
	// suspend current thread, and return 0 when resumed
	thread.suspend(0);
	// resume some other thread
	this->wakeup_next();
	return true;
}
void MultiThreading::erase_thread(int tid)
{
	auto it = m_threads.find(tid);
	assert(it != m_threads.end());
	m_threads.erase(it);
}
void MultiThreading::wakeup_next()
{
	// resume a waiting thread
	assert(!m_suspended.empty());
	auto* next = m_suspended.front();
	m_suspended.erase(m_suspended.begin());
	// resume next thread
	next->resume();
}


void Machine::setup_multithreading()
{
	Machine::install_syscall_handler(
		24, [] (auto& machine) { // sched_yield
			THPRINT("sched_yield on tid=%d\n",
				machine.threads().get_thread().tid);
			machine.threads().suspend_and_yield();
		});
	Machine::install_syscall_handler(
		56, [] (auto& machine) { // clone
			auto regs = machine.registers();
			const auto flags = regs.rdi;
			const auto stack = regs.rsi;
			const auto ptid  = regs.rdx;
			const auto ctid  = regs.r10;
			const auto tls   = regs.r8;
			const auto func  = regs.r12; /* NOTE: Only a guess */

			auto& parent = machine.threads().get_thread();
			auto& thread = machine.threads().create(flags, ctid, ptid, stack, tls);
			THPRINT(">>> clone(func=0x%llX, stack=0x%llX, flags=%llX,"
					" parent=%d, ctid=0x%llX ptid=0x%llX, tls=0x%llX) = %d\n",
					func, stack, flags, parent.tid, ctid, ptid, tls, thread.tid);
			// store return value for parent: child TID
			parent.suspend(thread.tid);
			// activate and return 0 for the child
			regs = thread.activate();
			regs.rax = 0;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler( // exit
		60, [] (auto& machine) {
			auto regs = machine.registers();
			const uint32_t status = regs.rdi;
			auto& thread = machine.threads().get_thread();
			THPRINT(">>> Exit on tid=%d, exit code = %d\n",
					thread.tid, (int) status);
			if (thread.tid != 0) {
				thread.exit();
				return;
			}
			machine.stop();
		});
	Machine::install_syscall_handler( // exit_group
		231, Machine::get_syscall_handler(60));
	Machine::install_syscall_handler(
		186, [] (auto& machine) {
			/* SYS gettid */
			auto regs = machine.registers();
			regs.rax = machine.threads().get_thread().tid;
			THPRINT("gettid() = %lld\n", regs.rax);
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		202, [] (Machine& machine) {
			/* SYS futex */
			auto regs = machine.registers();
			const auto addr = regs.rdi;
			const auto futex_op = regs.rsi;
			const uint32_t val = regs.rdx;
			THPRINT("Futex on: 0x%llX  val=%d\n", regs.rdi, val);
			auto* fx = machine.rw_memory_at<uint32_t>(addr, 4);

			if ((futex_op & 0xF) == FUTEX_WAIT) {
				THPRINT("FUTEX: Waiting for unlock... uaddr=%u val=%u\n", *fx, val);
				if (*fx == val) {
					if (machine.threads().suspend_and_yield()) {
						return;
					}
					throw std::runtime_error("DEADLOCK_REACHED");
				}
				regs.rax = 0;
			} else if ((futex_op & 0xF) == FUTEX_WAKE) {
				THPRINT("FUTEX: Waking others on uaddr=0x%lX, val=%u\n", (long) addr, val);
				if (machine.threads().suspend_and_yield()) {
					return;
				}
				regs.rax = 0;
			}
			else {
				throw std::runtime_error("Unimplemented futex op");
			}
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		218, [] (auto& machine) {
			/* SYS set_tid_address */
			auto regs = machine.registers();
#ifdef ENABLE_GUEST_VERBOSE
			THPRINT("Set TID address: clear_child_tid=0x%llX\n", regs.rdi);
#endif
			auto& thread = machine.threads().get_thread();
			/* Sets clear_tid and returns tid */
			thread.clear_tid = regs.rdi;
			regs.rax = thread.tid;
			machine.set_registers(regs);
		});
	Machine::install_syscall_handler(
		234, [] (auto& machine) { // TGKILL
			fprintf(stderr, "ERROR: tgkill called from tid=%d\n",
				machine.threads().get_thread().tid);
			machine.stop();
		});
	Machine::install_syscall_handler(
		273, [] (auto& machine) {
			/* SYS set_robust_list */
			auto regs = machine.registers();
			regs.rax = -ENOSYS;
			machine.set_registers(regs);
		});
} // setup_multithreading

} // tinykvm
