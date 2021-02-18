[BITS 64]
global vm64_entry
global vm64_exception
global vm64_end

%macro CPU_EXCEPT 1
ALIGN 0x10
	push rax
	mov rax, 0xffffa000 + %1
	mov DWORD [rax], 0
%endmacro
%macro CPU_EXCEPT_CODE 1
ALIGN 0x10
	push rax
	mov rax, 0xffffa000 + %1
	mov DWORD [rax], 0
%endmacro

org 0x100000
.vm64_entry:
	;; Test syscall 0 via MMIO
	mov rax, 0xffffa000
	mov WORD [rax], 1234
	;; Hello to stdout
	mov ax, 'H'
	out 0xe9, ax
	mov ax, 'e'
	out 0xe9, ax
	mov ax, 'l'
	out 0xe9, ax
	mov ax, 'l'
	out 0xe9, ax
	mov ax, 'o'
	out 0xe9, ax
	mov ax, '!'
	out 0xe9, ax
	push rax
	pop  rax

	;; Test syscall 0 via MMIO
	mov rax, 0xffffa000
	mov WORD [rax], 1234
	;; Test syscall 1 via MMIO
	mov rax, 0xffffa001
	mov WORD [rax], 1234
	;; Test syscall 2 via MMIO
	mov rax, 0xffffa002
	mov WORD [rax], 1234
	;; Cause exception
	ud2

ALIGN 0x10
.vm64_exception:
	CPU_EXCEPT 0
	CPU_EXCEPT 1
	CPU_EXCEPT 2
	CPU_EXCEPT 3
	CPU_EXCEPT 4
	CPU_EXCEPT 5
	CPU_EXCEPT 6
	CPU_EXCEPT 7
	CPU_EXCEPT_CODE 8
	CPU_EXCEPT 9
	CPU_EXCEPT_CODE 10
	CPU_EXCEPT_CODE 11
	CPU_EXCEPT_CODE 12
	CPU_EXCEPT_CODE 13
	CPU_EXCEPT_CODE 14
	CPU_EXCEPT 15
	CPU_EXCEPT 16
	CPU_EXCEPT_CODE 17
	CPU_EXCEPT 18
	CPU_EXCEPT 19
	CPU_EXCEPT 20

_strlen:
	push rbx
	push rcx

	mov   rbx, rdi
	xor   al,  al
	mov   rcx, 0xffffffff

	repne scasb               ; REPeat while Not Equal [edi] != al

	sub   rdi, rbx            ; length = offset of (edi - ebx)
	mov   rax, rdi

	pop rbx
	pop rcx
	ret

section .data
message: db "Hello World!", 0xa, 0x0

.vm64_end:
