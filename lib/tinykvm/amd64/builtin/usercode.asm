[BITS 64]

dw .vm64_entry
dw .vm64_rexit
dw .vm64_preserving_entry
dw 0
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
	mov rcx, r13
	jmp r15
;; The exit function (pre-written to stack)
.vm64_rexit:
	mov rdi, rax
.vm64_rexit_retry:
	mov eax, 0xFFFF
	out 0, eax
	jmp .vm64_rexit_retry
.vm64_preserving_entry:
	;; This is the entry point for a paused VM where
	;; its in the middle of a user program, so every
	;; register must be preserved. We need to flush
	;; the pagetables to ensure the guest can see the
	;; correct memory. Since the guest is potentially
	;; blind here, the host has pushed the registers
	;; necessary to perform the syscall safely.
	mov rax, 0x1F777
	syscall
	pop r11 ;; used by syscall for rflags
	pop rcx ;; used by syscall for rip
	pop rax
	;; With the registers restored, we can now
	;; return to the guest program.
	ret


%macro  vcputable 1 
	dd %1
	dd 0
	dd 0
	dd 0
%endmacro

ALIGN 0x8
.vm64_cpuid:
	vcputable 0
	vcputable 1
	vcputable 2
	vcputable 3
	vcputable 4
	vcputable 5
	vcputable 6
	vcputable 7
	vcputable 8
	vcputable 9
	vcputable 10
	vcputable 11
	vcputable 12
	vcputable 13
	vcputable 14
	vcputable 15
	vcputable 16
.vm64_cpuid_end:
