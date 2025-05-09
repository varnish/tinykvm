[BITS 64]
global vm64_exception

;; CPU exception frame:
;; 1. stack    rsp+32
;; 2. rflags   rsp+24
;; 3. cs       rsp+16
;; 4. rip      rsp+8
;; 5. code     rsp+0
%macro CPU_EXCEPT 1
ALIGN 0x8
	out 128 + %1, ax
	iretq
%endmacro
%macro CPU_EXCEPT_CODE 1
ALIGN 0x8
	out 128 + %1, ax
	jmp .vm64_pop_code
%endmacro
%macro CPU_EXCEPT_PF 1
ALIGN 0x8
	jmp .vm64_page_fault
%endmacro

dw .vm64_syscall
dw .vm64_gettimeofday
dw .vm64_exception
dw .vm64_except1 - .vm64_exception
dw .vm64_dso
.clock_gettime_uses_rdtsc:
dw 1 ;; clock_gettime_uses_rdtsc

ALIGN 0x10
.vm64_syscall:
	cmp ax, 158 ;; PRCTL
	je .vm64_prctl
	cmp ax, 228 ;; CLOCK_GETTIME
	je .vm64_clock_gettime
	cmp eax, 0x1F777 ;; ENTRY SYSCALL
	je .vm64_entrycall
	cmp eax, 0x1F707 ;; REENTRY SYSCALL
	je .vm64_reentrycall
	out 0, eax
	o64 sysret

.vm64_prctl:
	stac
	push rsi
	push rcx
	push rdx
	cmp rdi, 0x1002 ;; PRCTL: SET_FS
	jne .vm64_prctl_get
	;; SET_FS := rsi
	mov ecx, 0xC0000100  ;; FSBASE
	mov eax, esi ;; low-32 FS base
	shr rsi, 32
	mov edx, esi ;; high-32 FS base
	wrmsr
	xor rax, rax ;; return 0
.vm64_prctl_end:
	pop rdx
	pop rcx
	pop rsi
	clac
	o64 sysret
.vm64_prctl_get:
	cmp rdi, 0x1003 ;; PRCTL: GET_FS
	jne .vm64_prctl_trap
	;; GET_FS [rsi] := FSBASE
	mov ecx, 0xC0000100  ;; FSBASE
	rdmsr
	shl rdx, 32   ;; lift high-32 FS base
	or  rdx, rax  ;; low-32 FS base
	mov [rsi], rax
	xor rax, rax ;; return 0
	jmp .vm64_prctl_end

.vm64_prctl_trap:
	;; PRCTL fallback to host syscall trap
	out 0, ax
	jmp .vm64_prctl_end

.vm64_clock_gettime:
	;; Emulate CLOCK_GETTIME syscall
	;; rdi = clockid
	;; rsi = timespec
	cmp rdi, 0 ;; CLOCK_REALTIME
	je .vm64_clock_gettime_trap
	stac
	push rax
	push rcx
	push rdx
	;; Check if clock_gettime_uses_rdtsc using RIP-relative addressing
	mov ax, [0x2000 + .clock_gettime_uses_rdtsc]
	cmp rax, 0
	je .vm64_clock_gettime_syscall
	;; TSC puts 64-bit timestamp in EAX:EDX
	rdtsc
	mov     ecx, eax
	mov     eax, eax
	shl     rdx, 32
	or      rax, rdx
	;; Convert TSC to nanoseconds
	;; 1 TSC = 1.0 / 4.0 GHz = 0.25 ns
	shr     rax, 2
	;; Set tv_sec and tv_nsec
	mov     rdx, 4835703278458516699
	mul     rdx
	shr     rdx, 18
	imul    rax, rdx, 1000000
	sub     rcx, rax
	mov     rax, rcx
	mov [rsi], rax     ;; seconds
	mov [rsi + 8], rdx ;; nanoseconds
	;; Restore registers
	pop rdx
	pop rcx
	pop rax
	clac
	;; Return to the caller
	mov eax, 0
	o64 sysret
.vm64_clock_gettime_syscall:
	;; Restore registers
	pop rdx
	pop rcx
	pop rax
	clac
.vm64_clock_gettime_trap:
	out 0, ax
	o64 sysret

.vm64_gettimeofday:
	mov eax, 96 ;; gettimeofday
	out 0, ax
	ret

.vm64_dso:
	mov eax, .vm64_gettimeofday
	ret

.vm64_entrycall:
	;; Reset pagetables
	mov rax, cr3
	mov cr3, rax
	o64 sysret

.vm64_reentrycall:
	o64 sysret

.vm64_page_fault:
	push rdi
	mov rdi, cr2
	out 128 + 14, ax
	invlpg [rdi]
	pop rdi

.vm64_pop_code:
	add rsp, 8
	iretq

.vm64_timeout:
	out 128 + 33, ax
	iretq

ALIGN 0x8
.vm64_exception:
	CPU_EXCEPT 0
ALIGN 0x8
.vm64_except1:
	CPU_EXCEPT 1
	CPU_EXCEPT 2
	CPU_EXCEPT 3
	CPU_EXCEPT 4
	CPU_EXCEPT 5
	CPU_EXCEPT 6
	CPU_EXCEPT 7
	CPU_EXCEPT_CODE 8  ;; double fault
	CPU_EXCEPT 9
	CPU_EXCEPT_CODE 10
	CPU_EXCEPT_CODE 11
	CPU_EXCEPT_CODE 12
	CPU_EXCEPT_CODE 13
	CPU_EXCEPT_PF 14
	CPU_EXCEPT 15
	CPU_EXCEPT 16
	CPU_EXCEPT_CODE 17
	CPU_EXCEPT 18
	CPU_EXCEPT 19
	CPU_EXCEPT 20
	ALIGN 0x8 ;; timer interrupt
		jmp .vm64_timeout
