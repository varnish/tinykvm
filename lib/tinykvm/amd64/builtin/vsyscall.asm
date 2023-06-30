[BITS 64]

org 0xFFFFFFFFFF600000
.vsyscall_gettimeofday:
	mov ax, 96 ;; gettimeofday
	out 0, ax
	ret
