#pragma once
#include "common.hpp"
#include "forward.hpp"
#include <mutex>

namespace tinykvm
{
	struct Machine;

	struct vCPU
	{
		void init(int id, Machine&, const MachineOptions&);
		void smp_init(int id, Machine &);
		void deinit();
		tinykvm_regs& registers();
		const tinykvm_regs& registers() const;
		void set_registers(const struct tinykvm_regs &);
#if defined(TINYKVM_ARCH_ARM64)
		void flush_registers() const;
		void invalidate_register_cache() const;
#endif
		tinykvm_fpuregs fpu_registers() const;
		void set_fpu_registers(const struct tinykvm_fpuregs &);
		const struct kvm_sregs& get_special_registers() const;
		struct kvm_sregs& get_special_registers();
		void set_special_registers(const struct kvm_sregs &);

		void run(uint32_t tix);
		long run_once();
		void stop() { stopped = true; }
		void disable_timer();
		std::string_view io_data() const;

		bool is_usermode() const;
		bool is_kernelmode() const;
		void enter_usermode();
		/* ARM64: build a resumable EL0 usermode register frame from a vCPU
		   parked inside a syscall handler (PC<-ELR_EL1, SP<-SP_EL0, pstate=EL0T,
		   GP regs kept). Call from within the handler, before the run loop
		   returns, while x0..x30 are still the user's pristine values. */
		tinykvm_regs usermode_frame_from_syscall() const;

		void print_registers() const;
		void handle_exception(uint64_t intr);
		unsigned exception_extra_offset(uint8_t intr);
		void decrement_smp_count();

		auto& machine() { return *m_machine; }
		const auto& machine() const { return *m_machine; }
		void set_machine(Machine* m) { m_machine = m; }
		void set_original_machine(Machine* m) {
			this->m_original_machine = m;
		}
		Machine* original_machine() const { return this->m_original_machine; }

		void set_vcpu_table_at(unsigned index, int value);
		bool timed_out() const;

		int fd = -1;
		int cpu_id = 0;
		bool stopped = true;
		bool m_permanent_remote_connected = false;
		uint8_t current_exception = 0;
		uint32_t timer_ticks = 0;
		void* timer_id = nullptr;
		uint64_t last_fault_address = 0;
		uint64_t remote_return_address = 0;
		uint64_t remote_original_tls_base = 0;
		std::mutex* remote_serializer = nullptr;

	private:
		struct kvm_run* kvm_run = nullptr;
		Machine* m_machine = nullptr;
		Machine* m_original_machine = nullptr;
#if defined(TINYKVM_ARCH_ARM64)
		mutable tinykvm_regs m_cached_regs {};
		mutable bool m_regs_cached = false;
		mutable bool m_regs_dirty = false;
#endif

		uint64_t vcpu_table_addr() const noexcept;
	};

} // namespace tinykvm
