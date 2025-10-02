int main() {
}
asm(".global sys_send\n"
	".type sys_send, @function\n"
	"sys_send:\n"
	"	mov $0x10000, %eax\n"
	"	out %eax, $0\n"
	"   ret\n");
asm(".global sys_recv\n"
	".type sys_recv, @function\n"
	"sys_recv:\n"
	"	mov $0x10001, %eax\n"
	"	out %eax, $0\n"
	"   ret\n");
extern void sys_send(const void* buf, unsigned len);
extern void sys_recv(void* buf, unsigned len);

void caller() {
    char buf[4096];
    sys_send(buf, sizeof(buf));
}
void resumer() {
    char buf[4096];
    sys_recv(buf, sizeof(buf));
}
