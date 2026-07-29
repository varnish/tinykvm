#pragma once
#include "common.hpp"
#include "forward.hpp"
#include <mutex>
#include <sys/types.h>

namespace tinykvm
{
	struct Machine;
	struct VmGroupSeat;

	struct vCPU
	{
		void init(int kvm_vcpu_id, int guest_cpu_index, Machine&, const MachineOptions&);
		void smp_init(int id, Machine &);
		void deinit();
		/* Pooled member: take over a VM group seat, creating its vCPU on
		   first use and adopting it (fd, kvm_run mapping, timer) afterwards.
		   guest_cpu_index stays 0: the seat only owns the KVM_CREATE_VCPU id.
		   Both arches implement this; the per-seat one-time bring-up differs
		   (KVM_SET_CPUID2 on AMD64, KVM_ARM_VCPU_INIT on ARM64). */
		void init_from_seat(VmGroupSeat&, Machine&, const MachineOptions&);
		/* The anti-deinit. Hands fd, kvm_run and timer back to the seat
		   without closing or unmapping anything: a struct kvm's vCPU capacity
		   is consumed permanently by every vCPU ever created in it, so
		   closing the fd would burn the seat instead of freeing it. */
		void detach_to_seat(VmGroupSeat&) noexcept;
#if !defined(TINYKVM_ARCH_ARM64)
		/* Releases the shadow registers of a vCPU that never became mapped.
		   deinit() is only reached from ~Machine, which is never run for a
		   constructor that threw after vCPU init (eg. a fork that ran out of
		   working memory in setup_cow_mode). */
		~vCPU();
#endif
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
		/* The KVM_CREATE_VCPU argument. Unique within one struct kvm — under
		   VM pooling many machines share a VM, so this is group-unique and
		   carries no guest-visible meaning. */
		int kvm_vcpu_id = 0;
		/* The guest-visible CPU index: PerVCPUTable slot, SMP TSS/IST math.
		   0 for every machine's main vCPU (incl. pooled forks); 1..k for a
		   machine's own SMP vCPUs. */
		int guest_cpu_index = 0;
		bool stopped = true;
		bool m_permanent_remote_connected = false;
		uint8_t current_exception = 0;
		uint32_t timer_ticks = 0;
		/* The thread timer_id below is bound to. Every assignment of
		   timer_id must set this too: it is what lets a VM group seat tell
		   whether the timer it is handing to its next tenant fires on the
		   tenant's thread or on a stale one. See Machine::create_vcpu_timer()
		   (SIGEV_THREAD_ID) and vCPU::detach_to_seat(). */
		pid_t timer_tid = 0;
		void* timer_id = nullptr;
		uint64_t last_fault_address = 0;
		uint64_t remote_return_address = 0;
		uint64_t remote_original_tls_base = 0;
		std::mutex* remote_serializer = nullptr;

	private:
#if !defined(TINYKVM_ARCH_ARM64)
		/* Map kvm_run now, if it isn't already. Called on the run path only:
		   see lazily_map_kvm_run(). */
		void ensure_kvm_run() {
			if (UNLIKELY(this->kvm_run == nullptr))
				this->lazily_map_kvm_run();
		}
		void lazily_map_kvm_run();
		void map_kvm_run();
		/* Point the register accessors at an existing kvm_run mapping. */
		void adopt_kvm_run(struct kvm_run*);
		/* The seat-independent tail of init(): extended control registers
		   and the SYSCALL/SYSRET MSRs, re-issued for every tenant. */
		void init_extended_state(Machine&);
#else
		/* ARM has no lazy/shadow register path (registers are read via
		   KVM_*_ONE_REG on the vCPU fd, not out of kvm_run->s.regs), so a
		   deferred mapping only needs to appear before the first KVM_RUN.
		   Called at the top of run_once(); a no-op once mapped. */
		void ensure_kvm_run();
		/* Run the EL1 TLB-flush stub if setup_cow_mode() deferred one. Called at
		   the top of run_once() so a fork/reset's TTBR0 swap is always flushed
		   before the guest executes with the new page tables, without paying the
		   flush (a guest run) at construction. Clears the flag before running the
		   stub, so the stub's own run_once() does not re-enter. */
		void flush_pending_guest_tlb();
#endif

		struct kvm_run* kvm_run = nullptr;
		Machine* m_machine = nullptr;
		Machine* m_original_machine = nullptr;
#if defined(TINYKVM_ARCH_ARM64)
		mutable tinykvm_regs m_cached_regs {};
		mutable bool m_regs_cached = false;
		mutable bool m_regs_dirty = false;
#else
		/* Canonical userspace register storage. It points into the shadow
		   below while a lazily mapped fork is unmapped, and into the mmap'ed
		   kvm_run->s.regs from the first run onwards. */
		struct kvm_regs*  m_regs = nullptr;
		struct kvm_sregs* m_sregs = nullptr;
		/* Shadow registers, owned while kvm_run is unmapped, and the
		   KVM_SYNC_X86_* bits to hand to KVM when the mapping appears. */
		void* m_shadow_regs = nullptr;
		uint32_t m_shadow_dirty_regs = 0;
		bool m_initialized = false;
#endif

		uint64_t vcpu_table_addr() const noexcept;
	};

} // namespace tinykvm
