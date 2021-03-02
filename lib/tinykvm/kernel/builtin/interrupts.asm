[BITS 64]
global vm64_exception

%macro CPU_EXCEPT 1
ALIGN 0x10
	push QWORD [rsp]
	;; exception trap
	mov ax, %1
	mov dx, 0xFFFF
	out dx, ax
%endmacro
%macro CPU_EXCEPT_CODE 1
ALIGN 0x10
	;; exception trap
	mov ax, %1
	mov dx, 0xFFFF
	out dx, ax
%endmacro

org 0x2000
.vm64_syscall:
	add eax, 0xffffa000
	mov DWORD [eax], 0
	jmp rcx

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
