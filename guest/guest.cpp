static const char text[] = "Hello World!\n";

asm(".global syscall\n"
"syscall:\n"
"	add $0xffffa000, %edi\n"
"	movl $0, (%rdi)\n"
"   ret\n");
extern "C" long syscall(int scall, ...);

int main()
{
	syscall(1, text, sizeof(text)-1);
	return 0;
}

extern "C"
void _start()
{
	syscall(0, main());
}
