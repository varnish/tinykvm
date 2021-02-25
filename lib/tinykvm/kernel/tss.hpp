#pragma once
#include <cstdint>

void setup_amd64_tss(struct kvm_sregs& sregs,
	uint64_t tss_addr, char* tss_ptr, uint64_t gdt_addr, char* gdt_ptr);
