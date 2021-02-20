[BITS 64]
global vm64_entry
global vm64_exception
global vm64_end

%macro CPU_EXCEPT 1
ALIGN 0x10
	push rax
	push rdx
	mov ax, %1
	mov dx, 0xFFFF
	out dx, ax
%endmacro
%macro CPU_EXCEPT_CODE 1
ALIGN 0x10
	push rax
	push rdx
	mov ax, %1
	mov dx, 0xFFFF
	out dx, ax
%endmacro

org 0x200000
.vm64_entry:
	;; Hello to stdout
	mov ax, 'H'
	out 1, ax
	mov ax, 'e'
	out 1, ax
	mov ax, 'l'
	out 1, ax
	mov ax, 'l'
	out 1, ax
	mov ax, 'o'
	out 1, ax
	mov ax, '!'
	out 1, ax
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

.vm64_end:
