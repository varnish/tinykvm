#pragma once
#include <algorithm>
#include <atomic>
#include <cassert>
#include <condition_variable>
#include <functional>
#include <future>
#include <mutex>
#include <queue>
#include <stdexcept>
#include <thread>

namespace tinykvm {

/**
 * Task queue for single thread
*/
class ThreadTask {
public:
	explicit ThreadTask(int nice, bool low_prio);
	auto enqueue(std::function<long()>) -> std::future<long>;
	void wait_until_empty();
	void wait_until_nothing_in_flight();
	void set_nice(int nice) { m_nice = nice; }
	void set_low_prio(bool low_prio) { m_prio_low = low_prio; }
	~ThreadTask();

private:
	void start_worker(std::unique_lock<std::mutex> const& lock);

	std::thread worker;
	// the task queue
	std::queue< std::packaged_task<long()> > tasks;
	// stop signal
	bool m_stop = false;
	// task thread priorities
	bool m_prio_low = false;
	int  m_nice = 0;

	// synchronization
	std::mutex queue_mutex;
	std::condition_variable condition_producers;
	std::condition_variable condition_consumers;

	std::mutex in_flight_mutex;
	std::condition_variable in_flight_condition;
	std::atomic<std::size_t> in_flight;

	struct handle_in_flight_decrement
	{
		ThreadTask& m_tp;

		handle_in_flight_decrement(ThreadTask& tp)
			: m_tp(tp)
		{ }

		~handle_in_flight_decrement()
		{
			std::size_t prev
				= std::atomic_fetch_sub_explicit(&m_tp.in_flight,
					std::size_t(1),
					std::memory_order_acq_rel);
			if (prev == 1)
			{
				std::unique_lock<std::mutex> guard(m_tp.in_flight_mutex);
				m_tp.in_flight_condition.notify_all();
			}
		}
	};
};

// the constructor just launches some amount of workers
inline ThreadTask::ThreadTask(int nice, bool low_prio)
	: m_prio_low { low_prio },
	  m_nice { nice },
	  in_flight(0)
{
	std::unique_lock<std::mutex> lock(this->queue_mutex);
	start_worker(lock);
}

// add new work item to the pool
inline auto ThreadTask::enqueue(std::function<long()> func) -> std::future<long>
{
	auto task = std::packaged_task<long()>(std::move(func));
	std::future<long> res = task.get_future();

	std::unique_lock<std::mutex> lock(queue_mutex);
	// don't allow enqueueing after stopping the pool
	if (m_stop)
		throw std::runtime_error("enqueue on stopped ThreadTask");

	tasks.push(std::move(task));
	std::atomic_fetch_add_explicit(&in_flight,
		std::size_t(1),
		std::memory_order_relaxed);
	condition_consumers.notify_one();

	return res;
}


// the destructor joins all threads
inline ThreadTask::~ThreadTask()
{
	std::unique_lock<std::mutex> lock(queue_mutex);
	m_stop = true;
	condition_consumers.notify_all();
	condition_producers.notify_all();
	condition_consumers.wait(lock); //, [this]{ return this->worker.joinable(); });
	this->worker.join();
	assert(in_flight == 0);
}

inline void ThreadTask::wait_until_empty()
{
	std::unique_lock<std::mutex> lock(this->queue_mutex);
	this->condition_producers.wait(lock,
		[this]{ return this->tasks.empty(); });
}

inline void ThreadTask::wait_until_nothing_in_flight()
{
	std::unique_lock<std::mutex> lock(this->in_flight_mutex);
	this->in_flight_condition.wait(lock,
		[this]{ return this->in_flight == 0; });
}

inline void ThreadTask::start_worker(
	std::unique_lock<std::mutex> const &lock)
{
	assert(lock.owns_lock() && lock.mutex() == &this->queue_mutex);
	(void)lock;

	this->worker = std::thread([this] {
		pthread_setschedprio(pthread_self(), this->m_nice);
		for(;;)
		{
			std::packaged_task<long()> task;
			bool notify;

			{
				std::unique_lock<std::mutex> lock(this->queue_mutex);
				this->condition_consumers.wait(lock,
					[this]{
						return this->m_stop || !this->tasks.empty();
					});

				// deal with shutdown
				if ((this->m_stop && this->tasks.empty()))
				{
					// detach this worker, effectively marking it stopped
					//this->worker.detach();
					this->condition_consumers.notify_all();
					return;
				}
				else if (!this->tasks.empty())
				{
					task = std::move(this->tasks.front());
					this->tasks.pop();
					notify = this->tasks.empty();
				}
				else
					continue;
			}

			handle_in_flight_decrement guard(*this);

			if (notify)
			{
				std::unique_lock<std::mutex> lock(this->queue_mutex);
				condition_producers.notify_all();
			}

			task();
		}
	});
}

} // tinykvm
