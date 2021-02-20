#pragma once
#include <cstddef>
#include <cstdint>

#define GDT_ACCESS_DUMMY  0x0
#define GDT_ACCESS_CODE   0x9A
#define GDT_ACCESS_DATA   0x92
#define GDT_ACCESS_CODE3  0xFA
#define GDT_ACCESS_DATA3  0xF2

extern void setup_amd64_segments(struct kvm_sregs&, uint64_t gdt_addr, char* gdt_ptr);

extern void GDT_write_segment(void* area, uint8_t flags);
extern void GDT_reload(uint16_t);
extern void print_gdt_entries(void* area, size_t count);
