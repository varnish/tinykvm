#include <cstdint>

#define NUM_IDT_ENTRIES   32

extern void set_exception_handler(void* area, uint8_t vec, uint64_t handler);
extern uint64_t sizeof_idt();
