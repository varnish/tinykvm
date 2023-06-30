#pragma once
#include <cstddef>
#include <cstdint>

extern void setup_amd64_segments(uint64_t gdt_addr, char* gdt_ptr);
extern void setup_amd64_segment_regs(struct kvm_sregs&, uint64_t gdt_addr);

extern void GDT_write_segment(void* area, uint8_t flags);
extern void GDT_write_TSS_segment(void* area, uint64_t tss_addr, uint32_t size);
extern void GDT_reload(uint16_t);
extern void print_gdt_entries(void* area, size_t count);
