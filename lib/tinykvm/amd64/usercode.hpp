#include <cstdint>
#include "../memory.hpp"
#include "memory_layout.hpp"

namespace tinykvm {

struct user_asm_header {
	uint16_t vm64_entry;
	uint16_t vm64_rexit;
	uint32_t vm64_cpuid;

	uint64_t translated_vm_entry(const vMemory& memory) const noexcept {
		return memory.physbase + USER_ASM_ADDR + vm64_entry;
	}
	uint64_t translated_vm_rexit(const vMemory& memory) const noexcept {
		return memory.physbase + USER_ASM_ADDR + vm64_rexit;
	}
	uint64_t translated_vm_cpuid(const vMemory& memory) const noexcept {
		return memory.physbase + USER_ASM_ADDR + vm64_cpuid;
	}
};
extern const user_asm_header& usercode_header();

extern void setup_vm64_usercode(void* usercode_area);

}
