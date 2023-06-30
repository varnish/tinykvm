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

#define tinykvm_regs    tinykvm_arm64regs
#define tinykvm_fpuregs tinykvm_arm64fpuregs

#endif

struct RSPClient;
}
