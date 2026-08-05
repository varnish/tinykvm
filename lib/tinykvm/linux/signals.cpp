#include "../machine.hpp"
#include "threads.hpp"
#if defined(TINYKVM_ARCH_ARM64)
#include "../arm64/memory_layout.hpp"
#else
#include "../amd64/idt.hpp"          // interrupt_header()
#include "../amd64/signal_frame.hpp" // guest_rt_sigframe
#include "../amd64/usercode.hpp"     // usercode_header()
#include <cstddef>
#include <cstring>
#endif
#include <cerrno>
#include <csignal>

namespace tinykvm {

namespace {

bool default_ignored_signal(int sig)
{
	switch (sig) {
	case SIGCHLD:
	case SIGCONT:
	case SIGURG:
	case SIGWINCH:
		return true;
	default:
		return false;
	}
}

int signal_tid(vCPU& cpu)
{
	return cpu.machine().threads().gettid();
}

#if !defined(TINYKVM_ARCH_ARM64)

static constexpr uint64_t RFLAGS_RESERVED1 = 1UL << 1;
static constexpr uint64_t RFLAGS_IF        = 1UL << 9;
static constexpr uint64_t RFLAGS_DF        = 1UL << 10;
static constexpr uint64_t RFLAGS_AC        = 1UL << 18;

/* The flag bits a handler is allowed to change through its ucontext, which is
   Linux's FIX_EFLAGS minus TF: single-stepping out of a handler would raise a
   #DB that this kernel has no way to hand back to the guest, so it would kill
   the VM rather than trap. AC is excluded too -- Linux restores it, but here
   it would resume usermode with the kernel's SMAP override still on. */
static constexpr uint64_t RFLAGS_HANDLER_WRITABLE =
	  (1UL << 0)  /* CF */ | (1UL << 2)  /* PF */ | (1UL << 4)  /* AF */
	| (1UL << 6)  /* ZF */ | (1UL << 7)  /* SF */ | (1UL << 10) /* DF */
	| (1UL << 11) /* OF */;

/* The interrupted usermode context, recovered from the frame captured at the
   port-I/O trap. Signals are only ever raised from a syscall handler, so the
   guest is parked at the `out` in the generic syscall stub: SYSCALL has
   already put the usermode RIP in RCX and the usermode RFLAGS in R11, and the
   stub pushed exactly one qword -- the TLB-invalidation indicator -- below the
   usermode RSP. */
struct InterruptedContext {
	uint64_t rip;
	uint64_t rflags;
	uint64_t rsp;
};
InterruptedContext interrupted_context(const tinykvm_regs& regs) noexcept
{
	return { regs.rcx, regs.r11, regs.rsp + 8 };
}

/* Usermode CS/SS as set up by amd64/gdt.cpp; FS and GS run with a null
   selector and a base written through the MSRs. */
static constexpr uint64_t USER_CS = 0x2B;
static constexpr uint64_t USER_SS = 0x23;

/* MXCSR bits the hardware defines; LDMXCSR #GPs on anything else, and
   KVM_SET_FPU rejects it, so a handler cannot smuggle one back in. */
static constexpr uint32_t MXCSR_MASK = 0xFFBF;

/* KVM_GET_FPU/KVM_SET_FPU move only the legacy 512-byte FXSAVE area, never the
   XSAVE header, and that bounds what these two can do in one corner: when the
   guest leaves *all* SSE state in its initial (zeroed) form, XSAVE's init
   optimisation clears XSTATE_BV[SSE] and stops maintaining xmm_space, so a read
   returns whatever was last written there and a write is discarded by XRSTOR in
   favour of zeroes. A handler that zeroes every vector register therefore loses
   the interrupted ones. Harmless in practice, and for the same reason the
   ABI-minded may wonder why this is worth doing at all: signals are only ever
   delivered at a syscall boundary, where SysV already makes every vector
   register caller-saved and hence dead. The save/restore is what keeps a
   handler's own SSE use -- any memcpy will do -- from being observable by the
   interrupted code, matching what Linux guarantees. */
void save_fpu_state(vCPU& cpu, guest_fpstate& fps)
{
	const auto fpu = cpu.fpu_registers();
	fps = {};
	fps.cwd = fpu.fcw;
	fps.swd = fpu.fsw;
	fps.twd = fpu.ftwx;
	fps.fop = fpu.last_opcode;
	fps.rip = fpu.last_ip;
	fps.rdp = fpu.last_dp;
	fps.mxcsr = fpu.mxcsr & MXCSR_MASK;
	fps.mxcsr_mask = MXCSR_MASK;
	std::memcpy(fps.st_space, fpu.fpr, sizeof(fps.st_space));
	std::memcpy(fps.xmm_space, fpu.xmm, sizeof(fps.xmm_space));
}

void restore_fpu_state(vCPU& cpu, const guest_fpstate& fps)
{
	tinykvm_fpuregs fpu {};
	fpu.fcw = fps.cwd;
	fpu.fsw = fps.swd;
	fpu.ftwx = uint8_t(fps.twd);
	fpu.last_opcode = fps.fop;
	fpu.last_ip = fps.rip;
	fpu.last_dp = fps.rdp;
	fpu.mxcsr = fps.mxcsr & MXCSR_MASK;
	std::memcpy(fpu.fpr, fps.st_space, sizeof(fpu.fpr));
	std::memcpy(fpu.xmm, fps.xmm_space, sizeof(fpu.xmm));
	cpu.set_fpu_registers(fpu);
}

#endif // !TINYKVM_ARCH_ARM64

} // namespace

Signals::Signals() = default;
Signals::Signals(const Signals&) = default;
Signals& Signals::operator=(const Signals&) = default;
Signals::~Signals() = default;

SignalAction& Signals::get(int sig) {
	if (sig > 0 && sig <= static_cast<int>(signals.size()))
		return signals.at(sig-1);
	throw MachineException("Signal out of range", sig);
}

void Signals::send(vCPU& cpu, int sig, int si_code)
{
	auto regs = cpu.registers();
	if (sig == 0) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}
	if (sig < 1 || sig > static_cast<int>(signals.size())) {
		regs.sysret() = -EINVAL;
		cpu.set_registers(regs);
		return;
	}

	const auto& sigact = get(sig);
	if (sigact.handler == 1 /* SIG_IGN */) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}
	if (sigact.is_deliverable()) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		enter(cpu, sig, si_code);
		return;
	}
	if (default_ignored_signal(sig)) {
		regs.sysret() = 0;
		cpu.set_registers(regs);
		return;
	}

	/* Terminated by an unhandled signal: make it look like exit(128+sig),
	   the shell convention, readable via Machine::return_value().
	   return_value() reads the *exit* register, not the syscall return one:
	   exit(2) takes its status in sysarg(0), and a returning vmcall has its
	   rax moved there by the .vm64_rexit stub. On ARM64 sysarg(0) and
	   sysret() are both x0, which is why setting only the latter used to
	   work there; on AMD64 they are rdi and rax, and rax is never read. */
	regs.sysarg(0) = 128 + sig;
	regs.sysret() = 128 + sig;
	cpu.set_registers(regs);
	cpu.stop();
}

void Signals::enter(vCPU& cpu, int sig, [[maybe_unused]] int si_code)
{
	if (sig <= 0) return;
	auto& sigact = get(sig);
	/* send() already filtered these out; belt and braces for direct callers,
	   since everything below jumps the guest straight at handler. */
	if (!sigact.is_deliverable()) return;

	/* The interrupted frame is captured mid-syscall: the guest is inside the
	   kernel stub that trapped out to us. Restoring it in sigreturn() drops
	   the guest back exactly where the signal arrived. */
	const int tid = signal_tid(cpu);
	auto& frames = per_thread(tid).sigret.frames;
	frames.push_back(cpu.registers());
	auto regs = frames.back();
	auto& stack = per_thread(tid).stack;

#if defined(TINYKVM_ARCH_ARM64)
	if (sigact.on_altstack()) {
		if (stack.ss_sp != 0x0) {
			regs.stackptr() = (stack.ss_sp + stack.ss_size) & ~uint64_t(0xF);
		}
	}

	regs.regs[0] = static_cast<__u64>(sig);
	regs.regs[30] = SIGRETURN_ADDR;
	regs.pc = sigact.handler;
	cpu.set_registers(regs);
#else
	const auto& memory = cpu.machine().main_memory();
	const auto irq = interrupted_context(regs);

	/* Pick the handler stack, following Linux's get_sigframe(). The default
	   is the interrupted stack below its 128-byte red zone, which also stays
	   clear of the TLB-invalidation slot the syscall stub pushed just under
	   the usermode rsp. SA_ONSTACK switches to the thread's alternate stack
	   instead, where no red zone applies. */
	uint64_t sp = irq.rsp - 128;
	if (sigact.on_altstack() && stack.is_enabled()) {
		sp = stack.ss_sp + stack.ss_size;
	}
	/* The FXSAVE image goes above the frame, 64-byte aligned... */
	const uint64_t fpstate_addr =
		(sp - sizeof(guest_fpstate)) & ~uint64_t(63);
	/* ...and the frame below it, aligned so that rsp+8 is 16-byte aligned on
	   entry -- the SysV guarantee a handler's own prologue relies on, and the
	   difference between a working handler and a #GP in its first movaps. */
	const uint64_t frame_addr =
		((fpstate_addr - sizeof(guest_rt_sigframe)) & ~uint64_t(0xF)) - 8;

	guest_rt_sigframe frame {};
	/* The handler's return address. Linux has no vDSO restorer on x86-64, so
	   a libc must supply sa_restorer; the fallback stub covers guests that
	   call rt_sigaction by hand without SA_RESTORER. */
	frame.pretcode = sigact.has_restorer() ? sigact.restorer
		: usercode_header().translated_vm_sigreturn(memory);

	frame.info.si_signo = sig;
	frame.info.si_errno = 0;
	frame.info.si_code  = si_code;
	/* getpid() is emulated as 0, so the guest sees a self-signal from pid 0
	   running as root -- consistent with the rest of the Linux emulation. */
	frame.info.sender_pid = 0;
	frame.info.sender_uid = 0;

	frame.uc.uc_flags = 0;
	frame.uc.uc_link  = 0;
	frame.uc.uc_stack = { stack.ss_sp, stack.ss_flags, 0, stack.ss_size };

	auto& gregs = frame.uc.uc_mcontext.gregs;
	gregs[REG_R8]  = regs.r8;
	gregs[REG_R9]  = regs.r9;
	gregs[REG_R10] = regs.r10;
	gregs[REG_R11] = irq.rflags;
	gregs[REG_R12] = regs.r12;
	gregs[REG_R13] = regs.r13;
	gregs[REG_R14] = regs.r14;
	gregs[REG_R15] = regs.r15;
	gregs[REG_RDI] = regs.rdi;
	gregs[REG_RSI] = regs.rsi;
	gregs[REG_RBP] = regs.rbp;
	gregs[REG_RBX] = regs.rbx;
	gregs[REG_RDX] = regs.rdx;
	gregs[REG_RAX] = regs.rax;
	/* SYSCALL leaves the return address in RCX and the flags in R11, and that
	   is exactly what Linux reports for a signal taken at a syscall. */
	gregs[REG_RCX] = irq.rip;
	gregs[REG_RSP] = irq.rsp;
	gregs[REG_RIP] = irq.rip;
	gregs[REG_EFL] = irq.rflags;
	gregs[REG_CSGSFS] = USER_CS | (USER_SS << 48); /* cs | gs<<16 | fs<<32 | ss<<48 */
	gregs[REG_ERR]     = 0;
	gregs[REG_TRAPNO]  = 0;
	gregs[REG_OLDMASK] = 0;
	gregs[REG_CR2]     = 0;
	frame.uc.uc_mcontext.fpregs = fpstate_addr;
	/* Signal masking is not emulated, so nothing is blocked. */
	frame.uc.uc_sigmask = 0;

	guest_fpstate fpstate;
	save_fpu_state(cpu, fpstate);

	cpu.machine().copy_to_guest(frame_addr, &frame, sizeof(frame));
	cpu.machine().copy_to_guest(fpstate_addr, &fpstate, sizeof(fpstate));

	/* Replace the whole frame rather than letting the syscall stub run its
	   sysret epilogue, which would restore the interrupted rsp. Instead we
	   enter a kernel trampoline that sysrets into the handler: rcx is the
	   sysret target and r11 the RFLAGS it loads. */
	regs.rdi = static_cast<__u64>(sig);
	/* Passed unconditionally, as Linux does: a handler declared without a
	   prototype, or one registered without SA_SIGINFO and later re-read with
	   it, still finds the frame where the ABI says it is. */
	regs.rsi = frame_addr + offsetof(guest_rt_sigframe, info);
	regs.rdx = frame_addr + offsetof(guest_rt_sigframe, uc);
	/* AL is the vector-register count for a variadic callee; zero it so a
	   handler declared without a prototype does not spill nonexistent
	   arguments. Also keeps a guest-physical CR3 out of usermode. */
	regs.rax = 0;
	regs.rsp = frame_addr;
	regs.rcx = sigact.handler;
	/* sysret loads RFLAGS from r11: the guest's flags at the syscall, minus
	   DF and AC (both must be clear on entry to a SysV function under SMAP),
	   plus IF and the always-set reserved bit 1 -- a handler entered with
	   interrupts masked could never be timed out. IOPL is deliberately kept:
	   guests run at IOPL 3 so the usermode exit stub can `out`. */
	regs.r11 = (irq.rflags & ~(RFLAGS_DF | RFLAGS_AC))
		| RFLAGS_IF | RFLAGS_RESERVED1;
	regs.rip = interrupt_header().translated_vm_signal_entry(memory);
	cpu.set_registers(regs);
#endif
}

void Signals::sigreturn(vCPU& cpu)
{
	const int tid = signal_tid(cpu);
	auto& frames = per_thread(tid).sigret.frames;
	if (frames.empty()) {
		cpu.stop();
		return;
	}
	const auto saved = frames.back();
	frames.pop_back();

#if defined(TINYKVM_ARCH_ARM64)
	cpu.set_registers(saved);
#else
	/* Return through the ucontext the handler was handed, not through the
	   frame we saved, so that a handler which edited it -- Go's async
	   preemption rewriting RIP/RSP to splice in a call, a libc siglongjmp --
	   gets what it asked for. The saved frame stays the authority for
	   anything the ucontext does not carry, and the fallback if it is
	   unreadable.

	   The guest reached rt_sigreturn from the restorer at [frame], which the
	   handler's `ret` already popped, and the syscall stub then pushed its
	   indicator slot: so the kernel-side rsp is the frame base again and the
	   ucontext sits one qword above it, exactly as Linux computes it. */
	const uint64_t uc_addr = cpu.registers().rsp + SIGFRAME_UC_OFFSET;
	guest_ucontext uc;
	try {
		cpu.machine().copy_from_guest(&uc, uc_addr, sizeof(uc));
	} catch (const MemoryException&) {
		/* A wild rt_sigreturn, or a handler that trashed its own stack.
		   Resume the interrupted context rather than fault in the kernel. */
		cpu.set_registers(saved);
		return;
	}

	const auto& gregs = uc.uc_mcontext.gregs;
	auto regs = saved;
	regs.r8  = gregs[REG_R8];
	regs.r9  = gregs[REG_R9];
	regs.r10 = gregs[REG_R10];
	regs.r12 = gregs[REG_R12];
	regs.r13 = gregs[REG_R13];
	regs.r14 = gregs[REG_R14];
	regs.r15 = gregs[REG_R15];
	regs.rdi = gregs[REG_RDI];
	regs.rsi = gregs[REG_RSI];
	regs.rbp = gregs[REG_RBP];
	regs.rbx = gregs[REG_RBX];
	regs.rdx = gregs[REG_RDX];
	regs.rax = gregs[REG_RAX];
	/* RCX and R11 are the sysret operands, so they cannot carry independent
	   values: the trampoline consumes them as the target RIP and RFLAGS.
	   That costs nothing in practice -- SYSCALL had already clobbered both at
	   the interruption point, which is why gregs[RCX]/gregs[R11] were filled
	   with exactly these two on the way in. */
	regs.rcx = gregs[REG_RIP];
	regs.rsp = gregs[REG_RSP];
	/* Only the arithmetic and direction flags come back from the handler.
	   Everything else -- IOPL above all -- comes from the frame captured at
	   delivery, so a guest cannot use sigreturn to grant itself privilege.
	   Note this restores the interrupted IF rather than forcing it: guests
	   run with interrupts masked (machine.cpp gives them RFLAGS 0x3002), and
	   execution timeouts do not depend on guest IF, so resuming with IF set
	   would hand the guest a state it never had. Delivery is the exception:
	   entry into a handler deliberately sets IF, see enter(). */
	regs.r11 = ((saved.r11 & ~(RFLAGS_HANDLER_WRITABLE | RFLAGS_AC))
		| (gregs[REG_EFL] & RFLAGS_HANDLER_WRITABLE))
		| RFLAGS_RESERVED1;
	regs.rip = interrupt_header().translated_vm_signal_return(
		cpu.machine().main_memory());

	if (uc.uc_mcontext.fpregs != 0x0) {
		try {
			guest_fpstate fpstate;
			cpu.machine().copy_from_guest(&fpstate,
				uc.uc_mcontext.fpregs, sizeof(fpstate));
			restore_fpu_state(cpu, fpstate);
		} catch (const MemoryException&) {
			/* Leave the FPU as the handler left it; the interrupted context
			   is at a syscall boundary, where the vector registers are
			   caller-saved and therefore already dead. */
		}
	}

	cpu.set_registers(regs);
#endif
}

SignalAction& Machine::sigaction(int sig)
{
	return signals().get(sig);
}

} // tinykvm
