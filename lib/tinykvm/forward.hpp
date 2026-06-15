#pragma once
struct kvm_run;
struct kvm_regs;
struct kvm_sregs;
struct kvm_lapic_state;
#include <linux/types.h>

namespace tinykvm {

#ifndef TINYKVM_ARCH
#define TINYKVM_ARCH_AMD64
#endif

#if defined(TINYKVM_ARCH_AMD64)

struct tinykvm_x86regs {
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;

	__u64& sysarg(unsigned n) {
		switch (n) {
		case 0: return rdi;
		case 1: return rsi;
		case 2: return rdx;
		case 3: return r10;
		case 4: return r8;
		default: return r9;
		}
	}
	const __u64& sysarg(unsigned n) const {
		return const_cast<tinykvm_x86regs*>(this)->sysarg(n);
	}
	__u64& sysret() { return rax; }
	const __u64& sysret() const { return rax; }
	__u64& stackptr() { return rsp; }
	const __u64& stackptr() const { return rsp; }
	__u64& progctr() { return rip; }
	const __u64& progctr() const { return rip; }
};

struct tinykvm_x86fpuregs {
	__u8  fpr[8][16];
	__u16 fcw;
	__u16 fsw;
	__u8  ftwx;  /* in fxsave format */
	__u8  pad1;
	__u16 last_opcode;
	__u64 last_ip;
	__u64 last_dp;
	__u8  xmm[16][16];
	__u32 mxcsr;
	__u32 pad2;
};

#define tinykvm_regs    tinykvm_x86regs
#define tinykvm_fpuregs tinykvm_x86fpuregs

#elif defined(TINYKVM_ARCH_ARM64)

struct tinykvm_arm64regs {
	__u64 regs[31];
	__u64 sp;
	__u64 pc;
	__u64 pstate;

	__u64& sysarg(unsigned n) { return regs[n < 6 ? n : 5]; }
	const __u64& sysarg(unsigned n) const { return regs[n < 6 ? n : 5]; }
	__u64& sysret() { return regs[0]; }
	const __u64& sysret() const { return regs[0]; }
	__u64& stackptr() { return sp; }
	const __u64& stackptr() const { return sp; }
	__u64& progctr() { return pc; }
	const __u64& progctr() const { return pc; }
};

struct tinykvm_arm64fpuregs {
	__u8 storage[528];
};

#define tinykvm_regs    tinykvm_arm64regs
#define tinykvm_fpuregs tinykvm_arm64fpuregs

#endif

struct RSPClient;
}
