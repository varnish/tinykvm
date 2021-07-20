#pragma once


namespace tinykvm {
	static constexpr uint64_t GDT_ADDR = 0x1600;
	static constexpr uint64_t TSS_ADDR = 0x1700;
	static constexpr uint64_t IDT_ADDR = 0x1800;
	static constexpr uint64_t INTR_ASM_ADDR = 0x2000;
	static constexpr uint64_t IST_ADDR = 0x3000;
	static constexpr uint64_t VSYS_ADDR = 0x4000;
	static constexpr uint64_t PT_ADDR  = 0x5000;
}
