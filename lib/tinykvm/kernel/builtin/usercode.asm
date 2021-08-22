[BITS 64]

org 0x4000
dw .vm64_entry
dw .vm64_rexit

ALIGN 0x10
.vm64_entry:
	;; XXX: This is a known problem.
	;; Page table races will trash this RCX eventually.
	;; You *need* to find a way to enter kernel mode
	;; without pushing to stack here.
	push rcx
	mov rax, 0x1F777
	syscall
	pop rcx
	;; Set RBP to 0x0 here?
	mov rax, rbp
	xor rbp, rbp
	jmp rax
.vm64_rexit:
	mov rdi, rax
.vm64_rexit_retry:
	mov ax, 0xFFFF
	out 0, ax
	jmp .vm64_rexit_retry
