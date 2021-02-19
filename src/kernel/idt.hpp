#include <cstdint>

#define NUM_IDT_ENTRIES   32

extern void set_exception_handler(void* area, uint8_t vec, uint64_t handler);
extern void print_exception_handlers(void* area);
extern uint64_t sizeof_idt();

extern const char* exception_name(uint8_t);
