#include <cstdint>

namespace tinykvm {

struct user_asm_header {
	uint16_t vm64_entry;
	uint16_t vm64_rexit;
	uint32_t vm64_cpuid;
};
extern const user_asm_header& usercode_header();

extern void setup_vm64_usercode(void* usercode_area);

}
