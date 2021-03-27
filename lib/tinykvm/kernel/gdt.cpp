#include "gdt.hpp"

#include <cstdio>
#include <cstring>
#include <linux/kvm.h>

#define GDT_ACCESS_DUMMY  0x0
#define GDT_ACCESS_TSS    0x09
#define GDT_ACCESS_CODE   0x9A
#define GDT_ACCESS_DATA   0x92
#define GDT_ACCESS_CODE3  0xFA
#define GDT_ACCESS_DATA3  0xF2

#define FLAGS_X32_PAGE 0xC
#define FLAGS_X64_PAGE 0xA
#define FLAGS_X64_TSS  0x0

struct GDT_desc
{
	uint16_t size;
	uint64_t offset;
} __attribute__((packed));

struct GDT_entry
{
	uint32_t limit_lo  : 16;
	uint32_t base_lo   : 24;
	uint32_t access    : 8;
	uint32_t limit_hi  : 4;
	uint32_t flags     : 4;
	uint32_t base_hi   : 8;
} __attribute__((packed));

void GDT_write_segment(void* area, uint8_t flags)
{
	auto* entry = (GDT_entry*) area;
	entry->limit_lo = 0xFFFF;
	entry->base_lo  = 0;
	entry->access   = flags;
	entry->limit_hi = 0xF;
	entry->flags    = FLAGS_X64_PAGE;
	entry->base_hi  = 0;
}
void GDT_write_TSS_segment(void* area, uint64_t tss_addr, uint32_t size)
{
	auto* entry = (GDT_entry*) area;
	entry->limit_lo = size;
	entry->limit_hi = 0;
	entry->access   = 0xE5;
	entry->flags    = FLAGS_X64_TSS;
	entry->base_lo  = tss_addr & 0xFFFFFF;
	entry->base_hi  = tss_addr >> 24;
}

void print_gdt_entries(void* area, size_t count)
{
	const auto* entry = (const GDT_entry*) area;
	for (size_t i = 0; i < count; i++) {
		const auto a = entry[i].access;
		const auto f = entry[i].flags;
		printf("GDT %2zx: P=%u DPL=%u S=%u Ex=%u DC=%u RW=%u G=%u Sz=%u L=%u\n",
			8*i, a >> 7, (a >> 5) & 0x3, (a >> 4) & 1, (a >> 3) & 1,
			a & 0x4, a & 0x2, f & 0x8, f & 0x4, f & 0x2);
	}
}

void setup_amd64_segments(uint64_t gdt_addr, char* gdt_ptr)
{
	/* Null segment */
	memset(gdt_ptr + 0x0, 0, 8);
	/* Kernel mode */
	GDT_write_segment(gdt_ptr + 0x8, GDT_ACCESS_CODE);
	GDT_write_segment(gdt_ptr + 0x10, GDT_ACCESS_DATA);
	/* Null user-base segment */
	memset(gdt_ptr + 0x18, 0, 8);
	/* User mode */
	GDT_write_segment(gdt_ptr + 0x20, GDT_ACCESS_DATA3);
	GDT_write_segment(gdt_ptr + 0x28, GDT_ACCESS_CODE3);

	/* TSS segment (initialized later) */
	memset(gdt_ptr + 0x30, 0, 8);
}

void setup_amd64_segment_regs(struct kvm_sregs& sregs, uint64_t gdt_addr)
{
	/* Code segment */
	struct kvm_segment seg = {
		.base = 0,
		.limit = 0xffffffff,
		.selector = 0x28,
		.type = 11, /* Code: execute, read, accessed */
		.present = 1,
		.dpl = 3, /* User-mode */
		.db = 0,
		.s = 1, /* Code/data */
		.l = 1, /* 64-bit */
		.g = 1, /* 4KB granularity */
	};
	sregs.cs = seg;

	/* Data segment */
	seg.type = 3; /* Data: read/write, accessed */
	seg.selector = 0x20;
	sregs.ds = sregs.es = sregs.ss = sregs.fs = sregs.gs = seg;

	/* GDT dtable */
	sregs.gdt.base  = gdt_addr;
	sregs.gdt.limit = sizeof(GDT_entry) * 7 - 1;
}
