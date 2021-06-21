[BITS 64]
global _start:function

SECTION .text
_start:
	mov di, 0x1337
	mov ax, 60  ;; exit
	o64 syscall
