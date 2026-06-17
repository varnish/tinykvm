#pragma once
#include <cstdint>

namespace tinykvm {
	static constexpr uint64_t VECTORS_ADDR = 0x8000;
	static constexpr uint64_t RET_STOP_ADDR = VECTORS_ADDR + 0x780;
	/* EL1 stub that invalidates the stage-1 TLB and stops. Must be run after
	   the host rewrites page tables / switches TTBR0_EL1: KVM does not
	   invalidate guest TLB entries for us (unlike a CR3 write on x86). */
	static constexpr uint64_t TLB_FLUSH_ADDR = VECTORS_ADDR + 0x790;
	/* EL0 trampoline a signal handler returns into. It issues rt_sigreturn so
	   the host can restore the interrupted frame saved by Signals::enter. */
	static constexpr uint64_t SIGRETURN_ADDR = VECTORS_ADDR + 0x7A8;
	static constexpr uint64_t PT_ADDR  = 0x9000;
	static constexpr uint64_t PT_SIZE  = 0x5000;
	static constexpr uint64_t VCPU_TABLE_ADDR = PT_ADDR + PT_SIZE;
	static constexpr uint64_t VCPU_TABLE_SIZE = 0x1000;
	/* Reserved MMIO address used by raw ARM64 guests to request a stop. */
	static constexpr uint64_t ARM64_STOP_MMIO_ADDR = 0xF0000000;
	/* Reserved MMIO addresses used by the EL1 vector page. These GPAs must
	   stay outside guest RAM and be stage-1 mapped so KVM can exit on them. */
	static constexpr uint64_t ARM64_SYSCALL_MMIO_ADDR = 0xF0001000;
	static constexpr uint64_t ARM64_FATAL_MMIO_ADDR = 0xF0002000;

}
