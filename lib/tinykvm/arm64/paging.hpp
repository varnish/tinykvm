#pragma once
#include "../paging.hpp"

namespace tinykvm {
	struct Machine;
	struct vCPU;

	void arm64_setup_el1_mmu(Machine&, vCPU&);
	/* Stage-2 (guest-physical) address width of VMs on this host,
	   captured from KVM_CAP_ARM_VM_IPA_SIZE at Machine::init(). */
	int arm64_vm_ipa_bits();
}
