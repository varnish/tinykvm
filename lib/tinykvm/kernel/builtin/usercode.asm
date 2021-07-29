[BITS 64]

org 0x4000
dw .vm64_entry
dw .vm64_rexit

ALIGN 0x10
.vm64_entry:
	push rax
	mov rax, 0x1F777
	syscall
	pop rax
	jmp rax
.vm64_rexit:
	mov rdi, rax
.vm64_rexit_retry:
	mov ax, 0xFFFF
	out 0, ax
	jmp .vm64_rexit_retry
