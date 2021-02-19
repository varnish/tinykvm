#include "idt.hpp"
#include <array>
#include <cstdio>

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

void set_exception_handler(void* area, uint8_t vec, uint64_t handler)
{
	auto* idt = (IDT*) area;
	set_entry(idt->entry[vec], handler, 0x8, IDT_PRESENT | IDT_CPL3 | IDT_GATE_INTR);
}

void print_exception_handlers(void* area)
{
	auto* idt = (IDT*) area;
	for (unsigned i = 0; i < NUM_IDT_ENTRIES; i++) {
		const auto& entry = idt->entry[i];
		addr_helper addr;
		addr.lo16 = entry.offset_1;
		addr.hi16 = entry.offset_2;
		addr.top32 = entry.offset_3;
		printf("IDT %u: func=0x%lX sel=0x%X p=%d dpl=%d type=0x%X\n",
			i, addr.whole, entry.selector, entry.type_attr >> 7,
			(entry.type_attr >> 5) & 0x3, entry.type_attr & 0xF);
	}
}


uint64_t sizeof_idt()
{
	return sizeof(IDT);
}

static std::array<const char*, 32> exception_names =
{
	"Divide-by-zero Error",
	"Debug",
	"Non-Maskable Interrupt",
	"Breakpoint",
	"Overflow",
	"Bound Range Exceeded",
	"Invalid Opcode",
	"Device Not Available",
	"Double Fault",
	"Reserved",
	"Invalid TSS",
	"Segment Not Present",
	"Stack-Segment Fault",
	"General Protection Fault",
	"Page Fault",
	"Reserved",
	"x87 Floating-point Exception",
	"Alignment Check",
	"Machine Check",
	"SIMD Floating-point Exception",
	"Virtualization Exception",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Reserved",
	"Security Exception",
	"Reserved"
};

const char* exception_name(uint8_t intr) {
	return exception_names.at(intr);
}
