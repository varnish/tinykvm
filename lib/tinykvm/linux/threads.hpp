#pragma once
#include "../forward.hpp"
#include <map>
#include <memory>
#include <utility>
#include <vector>

namespace tinykvm {
	struct Machine;
	struct MultiThreading;

struct Thread {
	struct MultiThreading& mt;
	const int tid;
	struct tinykvm_regs stored_regs;
	uint64_t fsbase;
	uint64_t clear_tid;
	/* Address this thread is blocked on via FUTEX_WAIT, or 0 if the thread is
	   runnable (suspended only because another thread is current). The
	   scheduler resumes runnable threads and skips futex-blocked ones; a
	   FUTEX_WAKE on a matching address clears this back to 0. */
	uint64_t futex_addr = 0;

	void suspend(uint64_t rv);
	struct tinykvm_regs activate();
	void resume();
	void exit();

	Thread(MultiThreading&, int tid, uint64_t tls, uint64_t stack);
	Thread(MultiThreading&, const Thread& other);
};

struct MultiThreading {
	Thread& get_thread();
	Thread* get_thread(int tid); /* or nullptr */
	int gettid() { return get_thread().tid; }

	Thread& create(int tid);
	Thread& create(int flags, uint64_t ctid, uint64_t ptid,
		uint64_t stack, uint64_t tls);
	/* Suspend the current thread and switch to the next runnable thread.
	   block_addr == 0 leaves the current thread runnable (a plain yield);
	   a non-zero block_addr marks it blocked on that futex address until a
	   matching FUTEX_WAKE. Returns false (and does not switch) if no other
	   runnable thread exists. */
	bool suspend_and_yield(int64_t result = 0, uint64_t block_addr = 0);
	/* Suspend the current thread (blocked on block_addr, or runnable when 0)
	   and resume `next`, which must currently be in the suspended set. */
	void switch_to(Thread* next, int64_t result = 0, uint64_t block_addr = 0);
	/* Mark up to max_count threads blocked on `addr` as runnable (does not
	   switch threads). Returns {number woken, first thread woken or nullptr}
	   so the caller can hand control straight to a woken waiter. */
	std::pair<size_t, Thread*> wake_futex(uint64_t addr, size_t max_count);
	void erase_thread(int tid);
	void wakeup_next();

	void reset_to(const MultiThreading& other);
	void set_to_and_suspend_others(int tid);
	size_t size() const { return m_threads.size(); }
	const std::map<int, Thread>& threads() const { return m_threads; }

	MultiThreading(Machine&);
	Machine& machine;
private:
	/* Peek the next runnable (futex_addr == 0) suspended thread in FIFO order
	   without removing it, or nullptr if every suspended thread is
	   futex-blocked. The caller removes it (switch_to / wakeup_next). */
	Thread* next_runnable();

	std::map<int, Thread> m_threads;
	std::vector<Thread*> m_suspended;
	Thread* m_current = nullptr;
	int thread_counter = 1;
	friend struct Thread;
};

}
