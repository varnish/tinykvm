[BITS 64]
global _start:function
global test:function
global rexit:function

SECTION .text

ALIGN 0x8
_start:
	mov di, 0x1337

	mov rsp, 0x1ff000
	push rdi

	mov ax, 60  ;; exit
	syscall

ALIGN 0x8
test:
	mov rsp, 0x1ff000
	push rax
	pop rax
	ret

ALIGN 0x8
rexit:
	mov rdi, rax
	mov rax, 60  ;; exit
	syscall
