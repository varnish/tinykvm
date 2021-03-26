#pragma once
#include "forward.hpp"
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
};

struct MultiThreading {
	Thread& get_thread();
	Thread* get_thread(int tid); /* or nullptr */

	Thread& create(int flags, uint64_t ctid, uint64_t ptid,
		uint64_t stack, uint64_t tls);
	bool suspend_and_yield();
	void erase_thread(int tid);
	void wakeup_next();

	MultiThreading(Machine&);
	Machine& machine;
private:
	std::map<int, Thread> m_threads;
	std::vector<Thread*> m_suspended;
	Thread* m_current = nullptr;
	Thread main_thread;
	int thread_counter = 0;
	friend struct Thread;
};

}
