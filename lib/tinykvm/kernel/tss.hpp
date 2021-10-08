#pragma once
#include <cstdint>
struct kvm_sregs;

namespace tinykvm {

extern void setup_amd64_tss(
	uint64_t tss_addr, char* tss_ptr, char* gdt_ptr);

extern void setup_amd64_tss_smp(
	char* smp_tss_ptr);

extern void setup_amd64_tss_regs(struct kvm_sregs& sregs, uint64_t tss_addr);

}
