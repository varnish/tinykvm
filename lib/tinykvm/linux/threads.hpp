#pragma once
#include "../forward.hpp"
#include <map>
#include <memory>
#include <vector>

namespace tinykvm {
	struct Machine;
	struct MultiThreading;

struct Thread {
	struct MultiThreading& mt;
	const int tid;
	struct tinykvm_x86regs stored_regs;
	uint64_t fsbase;
	uint64_t clear_tid;

	void suspend(uint64_t rv);
	struct tinykvm_x86regs activate();
	void resume();
	void exit();

	Thread(MultiThreading&, int tid, uint64_t tls, uint64_t stack);
	Thread(MultiThreading&, const Thread& other);
};

struct MultiThreading {
	Thread& get_thread();
	Thread* get_thread(int tid); /* or nullptr */
	int gettid() { return get_thread().tid; }

	Thread& create(int flags, uint64_t ctid, uint64_t ptid,
		uint64_t stack, uint64_t tls);
	bool suspend_and_yield(int64_t result = 0);
	void erase_thread(int tid);
	void wakeup_next();

	void reset_to(const MultiThreading& other);

	MultiThreading(Machine&);
	Machine& machine;
private:
	std::map<int, Thread> m_threads;
	std::vector<Thread*> m_suspended;
	Thread* m_current = nullptr;
	int thread_counter = 1;
	friend struct Thread;
};

}
