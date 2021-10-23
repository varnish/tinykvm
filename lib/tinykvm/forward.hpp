#pragma once
struct kvm_run;
struct kvm_regs;
struct kvm_sregs;
struct kvm_lapic_state;
#include <linux/types.h>

namespace tinykvm {

struct tinykvm_x86regs {
	/* out (KVM_GET_REGS) / in (KVM_SET_REGS) */
	__u64 rax, rbx, rcx, rdx;
	__u64 rsi, rdi, rsp, rbp;
	__u64 r8,  r9,  r10, r11;
	__u64 r12, r13, r14, r15;
	__u64 rip, rflags;
};

}
