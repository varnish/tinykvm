#include "api.hpp"

asm(".global syscall\n"
"syscall:\n"
"	add $0xffffa000, %edi\n"
"	movl $0, (%rdi)\n"
"   ret\n");

asm(".global rexit\n"
"rexit:\n"
"	mov %rax, %rdi\n"
"   mov $0, %ax\n"
"	out %ax, $0\n");

asm(".global _start\n"
"_start:\n"
"	pop %rdi\n"
"	mov %rsp, %rsi\n"
"   call main\n"
"   jmp rexit\n");

extern "C" __attribute__((noreturn)) void exit(int code) __THROW {
	syscall(0, code);
	__builtin_unreachable();
}
