#pragma once
#include "machine.hpp"
#include <deque>
#include <functional>
#include <vector>
#include "util/threadpool.h"

namespace tinykvm
{
	struct SMP {
		using address_t = uint64_t;

		template <typename... Args>
		void timed_smpcall(size_t cpus,
			address_t stack, uint32_t stack_size,
			address_t addr, float tmo, Args&&...);
		void timed_smpcall_array(size_t cpus,
			address_t stack, uint32_t stack_size,
			address_t addr, float tmo,
			address_t array, uint32_t array_item_size);
		void timed_smpcall_clone(size_t num_cpus,
			address_t stack_base, uint32_t stack_size,
			float timeout, const tinykvm_x86regs& regs);

		int smp_active() const noexcept { return m_smp_active; }
		void wait();
		/* Retrieve return values from a smpcall */
		std::vector<long> gather_return_values(unsigned cpus = 0);

		void broadcast(std::function<void(vCPU&)>);

		Machine& machine() noexcept { return m_machine; }
		const Machine& machine() const noexcept { return m_machine; }

		struct MPvCPU_data
		{
			vCPU* vcpu = nullptr;
			uint32_t ticks = 0;
			struct tinykvm_x86regs regs;
		};
		struct MPvCPU
		{
			void blocking_message(std::function<void(vCPU &)>);
			void async_exec(struct MPvCPU_data &);

			MPvCPU(int, Machine &);
			~MPvCPU();
			vCPU cpu;
			ThreadPool thpool;
		};

		SMP(Machine& m) : m_machine{m} {}
		~SMP();
	private:
		MPvCPU_data* smp_allocate_vcpu_data(size_t);
		void prepare_cpus(size_t num_cpus);
		vCPU& smp_cpu(size_t idx);

		Machine& m_machine;
		std::deque<MPvCPU> m_cpus;
		std::vector<const struct MPvCPU_data *> m_smp_data;
		std::mutex m_smp_data_mtx;
		int m_smp_active = 0;

		friend struct vCPU;
	};

	template <typename... Args> inline
	void SMP::timed_smpcall(size_t num_cpus,
		address_t stack_base, uint32_t stack_size,
		address_t addr, float timeout, Args&&... args)
	{
		assert(num_cpus != 0);
		this->prepare_cpus(num_cpus);
		auto* data = smp_allocate_vcpu_data(num_cpus);

		/* XXX: This counter can be wrong when exceptions
		happen during setup_call and async_exec. */
		__sync_fetch_and_add(&m_smp_active, num_cpus);

		for (size_t c = 0; c < num_cpus; c++) {
			data[c].vcpu = &m_cpus[c].cpu;
			data[c].ticks = to_ticks(timeout);
			machine().setup_call(data[c].regs, addr,
				stack_base + (c+1) * stack_size,
				std::forward<Args> (args)...);
			m_cpus[c].async_exec(data[c]);
		}
	}

} // tinykvm
