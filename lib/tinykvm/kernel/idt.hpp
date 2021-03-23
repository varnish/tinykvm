#include <cstdint>

#define NUM_IDT_ENTRIES   32

extern void setup_amd64_exceptions(struct kvm_sregs&,
	uint64_t addr, void* area, void* code_area);

extern void set_exception_handler(void* area, uint8_t vec, uint64_t handler);
extern void print_exception_handlers(void* area);

extern const char* exception_name(uint8_t);

struct iasm_header {
	uint16_t vm64_syscall;
	uint16_t vm64_gettimeofday;
	uint16_t vm64_exception;
	uint16_t vm64_dso;
};
const iasm_header& interrupt_header();
