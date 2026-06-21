#pragma once
#include <cstdint>

namespace tinykvm {
	static constexpr uint64_t GDT_ADDR = 0x1600;
	static constexpr uint64_t TSS_ADDR = 0x1700;
	static constexpr uint64_t IDT_ADDR = 0x1800;
	static constexpr uint64_t INTR_ASM_ADDR = 0x2000;
	static constexpr uint64_t IST_ADDR = 0x3000;
	static constexpr uint64_t IST2_ADDR = 0x4000;
	static constexpr uint64_t IST_END_ADDR = 0x5000;
	/* Kernel control page (reuses the unused IST2 slot): a fork-private,
	   NX+RW data page the host uses to hand the syscall-return stub a
	   targeted TLB-invalidation request. Must be eagerly made fork-private
	   (see setup_cow_mode) so it is never CoW-cloned mid-syscall. */
	static constexpr uint64_t KERNEL_CTRL_ADDR = IST2_ADDR;
	/* Offset within the control page holding the TLB signal qword:
	   0 = nothing to flush, -1 = reload CR3, else = guest VA to invlpg. */
	static constexpr uint64_t KERNEL_CTRL_TLB_SIGNAL = 0x0;
	static constexpr uint64_t USER_ASM_ADDR = 0x5000;
	static constexpr uint64_t VSYS_ADDR = 0x6000;
	static constexpr uint64_t TSS_SMP_ADDR = 0x7000;
	static constexpr uint64_t TSS_SMP2_ADDR = 0x8000;
	// After the last fixed page, every page after
	// is a fixed page table directory. Any further
	// allocations happen using memory banks.
	static constexpr uint64_t PT_ADDR  = 0x9000;

	// The size of the interrupt stacks on each SMP
	// vCPU, offset from IST_ADDR. We allow 17 vCPUs.
	static constexpr uint64_t TSS_SMP_STACK = 240;
	// Maximum size of interrupt and exception frame
	static constexpr uint64_t INTR_STACK_FRAME = 48;
}
