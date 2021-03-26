[BITS 64]

org 0xFFFFFFFFFF600000
.vsyscall_gettimeofday:
	out 96, ax ;; gettimeofday
	ret
