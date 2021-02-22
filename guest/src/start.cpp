#include "api.hpp"

asm(".global syscall\n"
"syscall:\n"
"	add $0xffffa000, %edi\n"
"	movl $0, (%rdi)\n"
"   ret\n");

asm(".global native_syscall\n"
"native_syscall:\n"
"	mov %rdi, %rax\n"
"	mov %rsi, %rdi\n"
"	mov %rdx, %rsi\n"
"	mov %rcx, %rdx\n"
"	syscall\n"
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
"   call libc_start\n"
"   jmp rexit\n");


extern int main(int, char**);

extern "C"
int libc_start(int argc, char** argv)
{
	/* Global constructors */
	extern void(*__init_array_start [])();
	extern void(*__init_array_end [])();
	const int count = __init_array_end - __init_array_start;
	for (int i = 0; i < count; i++) {
		__init_array_start[i]();
	}

	return main(argc, argv);
}

extern "C" __attribute__((noreturn)) void exit(int code) __THROW {
	syscall(0, code);
	__builtin_unreachable();
}
