[BITS 64]

org 0x5000
dw .vm64_entry
dw .vm64_reentry
dw .vm64_rexit
dd .vm64_cpuid

ALIGN 0x10
;; The entry function, jumps to real function
.vm64_entry:
	;; Execute a pagetable flushing system call that
	;; ensures that even if we are entering in kernel mode,
	;; we are calling the user function in usermode.
	;; This cannot realistically be improved upon.
	mov r13, rcx
	mov rax, 0x1F777
	syscall
.vm64_user_jmp:
	mov rcx, r13
	jmp r15
;; Entry function that does not reset pagetables
.vm64_reentry:
	;; Execute a do-nothing system call that ensures
	;; that even if we are entering in kernel mode,
	;; we are calling the user function in usermode.
	;; This can be somewhat improved. Not worth the time.
	mov r13, rcx
	mov rax, 0x1F707
	syscall
	jmp .vm64_user_jmp
;; The exit function (pre-written to stack)
.vm64_rexit:
	mov rdi, rax
.vm64_rexit_retry:
	mov eax, 0xFFFF
	out 0, eax
	jmp .vm64_rexit_retry

.vm64_cpuid:
	dd 0
	dd 1
	dd 2
	dd 3
	dd 4
	dd 5
	dd 6
	dd 7
	dd 8
	dd 9
	dd 10
	dd 11
	dd 12
	dd 13
	dd 14
	dd 15
	dd 16
.vm64_cpuid_end:
