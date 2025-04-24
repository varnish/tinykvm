#include "threads.hpp"

#include "../machine.hpp"
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

Thread::Thread(MultiThreading& mtr, const Thread& other)
	: mt(mtr), tid(other.tid),
	  stored_regs{other.stored_regs},
	  fsbase{other.fsbase},
	  clear_tid{other.clear_tid}
{}

void Thread::suspend(uint64_t return_value)
{
	// GPRs
	stored_regs = mt.machine.registers();
	stored_regs.rax = return_value;
	// thread pointer
	const auto& sregs = mt.machine.get_special_registers();
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
		// clear the thread id in the parent
		const uint32_t value = 0;
		mt.machine.copy_to_guest(this->clear_tid, &value, sizeof(value));
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
	: machine(m)
{
	auto it = m_threads.try_emplace(1, *this, 1, 0x0, 0x0);
	m_current = &it.first->second;
}

void MultiThreading::reset_to(const MultiThreading& other)
{
	m_threads.clear();
	m_suspended.clear();

	/* Copy each thread, new MT ref */
	for (const auto& it : other.m_threads) {
		const int tid = it.first;
		const auto& thread = it.second;
		m_threads.try_emplace(tid, *this, thread);
	}
	/* Copy each suspended by pointer lookup */
	for (const auto* t : other.m_suspended) {
		m_suspended.push_back(get_thread(t->tid));
	}
	/* Translate current thread */
	m_current = get_thread(other.m_current->tid);

	thread_counter = other.thread_counter;
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
		// set the thread id in the child
		machine.copy_to_guest(ctid, &tid, sizeof(tid));
	}
	if (flags & CLONE_PARENT_SETTID) {
		THPRINT("PARENT_SETTID at 0x%lX\n", ptid);
		// set the thread id in the parent
		machine.copy_to_guest(ptid, &tid, sizeof(tid));
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

const struct MultiThreading& Machine::threads() const {
	if (UNLIKELY(!m_mt)) {
		m_mt.reset(new MultiThreading(*const_cast<Machine*>(this)));
	}
	return *m_mt;
}
struct MultiThreading& Machine::threads() {
	if (UNLIKELY(!m_mt)) {
		m_mt.reset(new MultiThreading(*this));
	}
	return *m_mt;
}

void Machine::setup_multithreading()
{
	Machine::install_syscall_handler(
		24, [] (vCPU& cpu) { // sched_yield
			THPRINT("sched_yield on tid=%d\n",
				cpu.machine().threads().get_thread().tid);
			cpu.machine().threads().suspend_and_yield();
		});
	Machine::install_syscall_handler(
		56, [] (vCPU& cpu) { // clone
			auto& regs = cpu.registers();
			const auto flags = regs.rdi;
			const auto stack = regs.rsi;
			const auto ptid  = regs.rdx;
			const auto ctid  = regs.r10;
			const auto tls   = regs.r8;
			const auto func  = regs.r9; /* NOTE: Only a guess */

			auto& parent = cpu.machine().threads().get_thread();
			auto& thread = cpu.machine().threads().create(flags, ctid, ptid, stack, tls);
			THPRINT(">>> clone(func=0x%llX, stack=0x%llX, flags=%llX,"
					" parent=%d, ctid=0x%llX ptid=0x%llX, tls=0x%llX) = %d\n",
					func, stack, flags, parent.tid, ctid, ptid, tls, thread.tid);
			// store return value for parent: child TID
			parent.suspend(thread.tid);
			// activate and return 0 for the child
			regs = thread.activate();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		435, [] (vCPU& cpu) { // clone3
			auto& regs = cpu.registers();

			static constexpr uint32_t SETTLS = 0x00080000;
			struct clone3_args {
				uint64_t flags;
				uint64_t pidfd;
				uint64_t child_tid;
				uint64_t parent_tid;
				uint64_t exit_signal;
				uint64_t stack;
				uint64_t stack_size;
				uint64_t tls;
				uint64_t set_tid_array;
				uint64_t set_tid_count;
				uint64_t cgroup;
			} args;
			if (regs.rsi < sizeof(clone3_args)) {
				regs.rax = -ENOSPC;
				return;
			}
			cpu.machine().copy_from_guest(&args, regs.rdi, sizeof(clone3_args));

			const auto flags = args.flags;
			const auto stack = args.stack + args.stack_size;
			const auto ptid  = args.parent_tid;
			const auto ctid  = args.child_tid;
			auto tls   = args.tls;
			if ((flags & SETTLS) == 0) {
				// Don't set TLS if not requested
				tls = cpu.get_special_registers().fs.base;
			}

			Thread& parent = cpu.machine().threads().get_thread();
			Thread& thread = cpu.machine().threads().create(flags, ctid, ptid, stack, tls);
			THPRINT(">>> clone3(stack=0x%lX, flags=%lX,"
					" parent=%d, ctid=0x%lX ptid=0x%lX, tls=0x%lX) = %d\n",
					stack, flags, parent.tid, ctid, ptid, tls, thread.tid);
			if (args.set_tid_count > 0) {
				uint64_t set_tid = 0;
				cpu.machine().copy_from_guest(&set_tid, args.set_tid_array, sizeof(set_tid));
				thread.clear_tid = set_tid;
			}

			// store return value for parent: child TID
			parent.suspend(thread.tid);
			// activate and return 0 for the child
			regs = thread.activate();
			regs.rax = 0;
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler( // exit
		60, [] (vCPU& cpu) {
			if (cpu.machine().has_threads()) {
				auto& regs = cpu.registers();
				[[maybe_unused]] const uint32_t status = regs.rdi;
				auto& thread = cpu.machine().threads().get_thread();
				THPRINT(">>> Exit on tid=%d, exit code = %d\n",
					thread.tid, (int) status);
				if (thread.tid != 1) {
					thread.exit();
					return;
				}
			}
			cpu.stop();
		});
	Machine::install_syscall_handler( // exit_group
		231, Machine::get_syscall_handler(60));
	Machine::install_syscall_handler(
		186, [] (vCPU& cpu) {
			/* SYS gettid */
			auto& regs = cpu.registers();
			if (cpu.machine().has_threads()) {
				regs.rax = cpu.machine().threads().get_thread().tid;
				THPRINT("gettid() = %lld\n", regs.rax);
			} else {
				regs.rax = 1; /* Main thread */
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		202, [] (vCPU& cpu) {
			/* SYS futex */
			auto& regs = cpu.registers();
			const auto addr = regs.rdi;
			const auto futex_op = regs.rsi;
			const uint32_t val = regs.rdx;
			THPRINT("Futex on: 0x%llX  val=%d\n", regs.rdi, val);

			if ((futex_op & 0xF) == FUTEX_WAIT || (futex_op & 0xF) == FUTEX_WAIT_BITSET) {
				uint32_t futexVal;
				cpu.machine().copy_from_guest(&futexVal, addr, sizeof(futexVal));
				THPRINT("FUTEX: Waiting for unlock... uaddr=%u val=%u\n", futexVal, val);
				if (futexVal == val) {
					if (cpu.machine().threads().suspend_and_yield()) {
						return;
					}
					// Deadlock reached. XXX: Force-unlock to continue
					// execution.
					THPRINT("FUTEX: Deadlock reached on uaddr=0x%lX, val=%u\n", (long) addr, val);
					futexVal = 0;
					cpu.machine().copy_to_guest(addr, &futexVal, sizeof(futexVal));
					regs.rax = 0;
					//throw std::runtime_error("DEADLOCK_REACHED");
				} else {
					regs.rax = 0;
				}
			} else if ((futex_op & 0xF) == FUTEX_WAKE || (futex_op & 0xF) == FUTEX_WAKE_BITSET) {
				THPRINT("FUTEX: Waking others on uaddr=0x%lX, val=%u\n", (long) addr, val);
				if (cpu.machine().threads().suspend_and_yield()) {
					return;
				}
				regs.rax = 0;
			}
			else {
				throw std::runtime_error("Unimplemented futex op: " + std::to_string(futex_op & 0xF));
			}
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		218, [] (vCPU& cpu) {
			/* SYS set_tid_address */
			auto& regs = cpu.registers();
			auto& thread = cpu.machine().threads().get_thread();
			/* Sets clear_tid and returns tid */
			thread.clear_tid = regs.rdi;
			regs.rax = thread.tid;
			THPRINT("set_tid_address(clear_tid=0x%lX) = %d\n",
				regs.rdi, thread.tid);
			cpu.set_registers(regs);
		});
	Machine::install_syscall_handler(
		234, [] (vCPU& cpu) { // TGKILL
			auto& regs = cpu.registers();
			[[maybe_unused]] int tid = 0;
			if (cpu.machine().has_threads()) {
				tid = cpu.machine().threads().get_thread().tid;
			}

			const int sig = regs.rdx;
			if (sig == 0) {
				THPRINT("tgkill(sig=0) called from tid=%d\n", tid);
				regs.rax = 0;
				cpu.set_registers(regs);
			} else {
				THPRINT("tgkill(sig=%d) called from tid=%d\n", sig, tid);
				cpu.machine().signals().enter(cpu, sig);
			}
		});
} // setup_multithreading

} // tinykvm
