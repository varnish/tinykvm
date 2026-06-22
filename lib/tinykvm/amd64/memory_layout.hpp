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

	// I/O port the generic syscall stub traps on (distinct from the plain
	// syscall port 0). Only this path reserves a stack slot for the TLB-
	// invalidation indicator, so the host writes that slot only for this
	// port. Must match SYSCALL_PORT in amd64/builtin/interrupts.asm.
	static constexpr uint32_t TINYKVM_SYSCALL_PORT = 0x10;

}
