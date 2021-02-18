#include "idt.hpp"

// 64-bit IDT entry
struct IDTentry {
	uint16_t offset_1;  // offset bits 0..15
	uint16_t selector;  // a code segment selector in GDT or LDT
	uint8_t  ist;       // 3-bit interrupt stack table offset
	uint8_t  type_attr; // type and attributes, see below
	uint16_t offset_2;  // offset bits 16..31
	uint32_t offset_3;  // 32..63
	uint32_t zero2;
};
static_assert(sizeof(IDTentry) == 16, "AMD64 IDT entries are 16-bytes");

#define IDT_GATE_INTR 0x0e
#define IDT_CPL0      0x00
#define IDT_CPL3      0x60
#define IDT_PRESENT   0x80

struct IDT
{
	IDTentry entry[NUM_IDT_ENTRIES];
};

union addr_helper {
	uint64_t whole;
	struct {
		uint16_t lo16;
		uint16_t hi16;
		uint32_t top32;
	};
};

static void set_entry(
	IDTentry& idt_entry,
	uint64_t handler,
	uint16_t segment_sel,
	uint8_t  attributes)
{
	addr_helper addr { .whole = handler };
	idt_entry.offset_1  = addr.lo16;
	idt_entry.offset_2  = addr.hi16;
	idt_entry.offset_3  = addr.top32;
	idt_entry.selector  = segment_sel;
	idt_entry.type_attr = attributes;
	idt_entry.ist       = 0;
	idt_entry.zero2     = 0;
}

void set_exception_handler(void* area, uint8_t vec, uint64_t handler) {
	auto* idt = (IDT*) area;
	set_entry(idt->entry[vec], handler, 0x8, IDT_PRESENT | IDT_CPL3 | IDT_GATE_INTR);
}

uint64_t sizeof_idt()
{
	return sizeof(IDT);
}
