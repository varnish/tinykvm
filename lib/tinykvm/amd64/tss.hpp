#pragma once
#include <cstdint>
struct kvm_sregs;

namespace tinykvm {
	struct vMemory;

extern void setup_amd64_tss(vMemory&);

extern void setup_amd64_tss_smp(vMemory&);

extern void setup_amd64_tss_regs(struct kvm_sregs& sregs, uint64_t tss_addr);

}
