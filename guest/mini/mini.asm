[BITS 64]
global _start:function
global test:function

SECTION .text
_start:
	mov di, 0x1337

	mov rsp, 0x1ff000
	push rdi

	mov ax, 60  ;; exit
	o64 syscall

test:
	push QWORD 0x7347
	pop rax
	ret

exit:
	mov rdi, rax
	mov ax, 60  ;; exit
	o64 syscall
