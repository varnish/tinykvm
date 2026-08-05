#pragma once
#include <cstdint>

/* The rt_sigframe the guest sees, byte-for-byte as Linux x86-64 builds it.
   Guests do not merely tolerate this layout, they parse it: every handler
   registered with SA_SIGINFO gets `info` in RSI and `uc` in RDX, and real
   runtimes read both. Go's runtime.sighandler dereferences info->si_code
   before it does anything else, and its sigctxt indexes uc_mcontext.gregs
   directly; glibc's SA_SIGINFO handlers and libgcc's unwinder do the same.

   Linux's own struct is

       struct rt_sigframe {
           char __user *pretcode;
           struct ucontext uc;
           struct siginfo info;
           // fp state follows here
       };

   with the FP state allocated *above* the frame and reached through
   uc.uc_mcontext.fpregs.

   The one trap here is uc_sigmask. The kernel's sigset_t is 8 bytes, while
   the sigset_t userspace declares (glibc, and Go's usigset) is 128. So the
   kernel's ucontext is 304 bytes, not the 968 of a userspace ucontext_t, and
   everything a guest reads past uc_sigmask's first 8 bytes is really the
   siginfo that follows. That is the actual Linux ABI, quirk included, so it
   is what we reproduce: matching the userspace struct instead would put
   uc_mcontext at the right offset but siginfo at the wrong one. */

namespace tinykvm {

struct guest_siginfo { /* kernel siginfo_t, _si_max_size */
	int32_t  si_signo;
	int32_t  si_errno;
	int32_t  si_code;
	int32_t  __pad0;
	/* union _sifields; the _kill variant is what a tgkill/kill delivery
	   fills, and si_addr of the _sigfault variant overlaps these two.
	   Deliberately not named si_pid/si_uid: glibc's <signal.h> defines both
	   as macros expanding to _sifields._kill.*, which would rewrite any use
	   of a member by that name here. */
	int32_t  sender_pid;
	uint32_t sender_uid;
	uint8_t  __pad1[128 - 24];
};
static_assert(sizeof(guest_siginfo) == 128, "kernel siginfo_t is 128 bytes");

struct guest_stack_t {
	uint64_t ss_sp;
	int32_t  ss_flags;
	int32_t  __pad;
	uint64_t ss_size;
};
static_assert(sizeof(guest_stack_t) == 24, "stack_t is 24 bytes");

/* struct _fpstate: the plain 512-byte FXSAVE image. Linux appends an
   xsave_hdr plus extended state when the CPU has XSAVE, and flags that by
   writing FP_XSTATE_MAGIC1 into sw_reserved; leaving sw_reserved zero is the
   legacy form and tells a guest there is nothing beyond the FXSAVE area. */
struct guest_fpstate {
	uint16_t cwd;
	uint16_t swd;
	uint16_t twd;
	uint16_t fop;
	uint64_t rip;
	uint64_t rdp;
	uint32_t mxcsr;
	uint32_t mxcsr_mask;
	uint8_t  st_space[128];  /* 8 x87 registers, 16 bytes each */
	uint8_t  xmm_space[256]; /* 16 XMM registers, 16 bytes each */
	uint8_t  reserved2[48];
	uint8_t  sw_reserved[48];
};
static_assert(sizeof(guest_fpstate) == 512, "FXSAVE image is 512 bytes");

/* struct sigcontext_64, which is also glibc's mcontext_t. The register order
   is the gregs[] index order, not a natural one -- see the REG_ enum. */
struct guest_sigcontext {
	uint64_t gregs[23];
	uint64_t fpregs; /* guest pointer to a guest_fpstate, or 0 */
	uint64_t reserved1[8];
};
static_assert(sizeof(guest_sigcontext) == 256, "sigcontext_64 is 256 bytes");

/* Indices into guest_sigcontext::gregs, from <sys/ucontext.h>. */
enum {
	REG_R8 = 0, REG_R9, REG_R10, REG_R11, REG_R12, REG_R13, REG_R14, REG_R15,
	REG_RDI, REG_RSI, REG_RBP, REG_RBX, REG_RDX, REG_RAX, REG_RCX, REG_RSP,
	REG_RIP, REG_EFL, REG_CSGSFS, REG_ERR, REG_TRAPNO, REG_OLDMASK, REG_CR2,
};

struct guest_ucontext { /* the *kernel* struct ucontext */
	uint64_t         uc_flags;
	uint64_t         uc_link;
	guest_stack_t    uc_stack;
	guest_sigcontext uc_mcontext;
	uint64_t         uc_sigmask; /* kernel sigset_t: one word, not 128 bytes */
};
static_assert(sizeof(guest_ucontext) == 304, "kernel ucontext is 304 bytes");

struct guest_rt_sigframe {
	uint64_t        pretcode; /* handler return address: the signal restorer */
	guest_ucontext  uc;
	guest_siginfo   info;
};
static_assert(sizeof(guest_rt_sigframe) == 440, "rt_sigframe is 440 bytes");

/* Where the guest's ucontext sits relative to the frame base, i.e. the value
   RSP has once the handler's `ret` has popped pretcode. rt_sigreturn reads
   the frame back from there. */
static constexpr uint64_t SIGFRAME_UC_OFFSET = 8;

} // tinykvm
