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

.read_system_time:
	push rbx
	push rcx
	push rdx
	;; Check if the system time MSR has already been set
	mov rax, [0x3030]    ;; system-time nanoseconds
	;; If the system time is zero, we need to set it
	test rax, rax
	jnz .system_time_already_set
	;; 0x4b564d01  MSR_KVM_SYSTEM_TIME_NEW
	mov ecx, 0x4b564d01  ;; MSR_KVM_SYSTEM_TIME_NEW
	mov eax, 0x3021      ;; data
	mov edx, 0           ;; zero high-32 bits
	wrmsr
.system_time_already_set:
	;; Read TSC
	rdtsc
	;; Add EDX to RAX for full 64-bit TSC value
	shl rdx, 32
	or  rax, rdx
	;; Calculate the system time in nanoseconds
	;; time = (current_tsc - tsc_timestamp)
	;; if (tsc_shift >= 0)
	;;         time <<= tsc_shift;
	;; else
	;;         time >>= -tsc_shift;
	;; time = (time * tsc_to_system_mul) >> 32
	;; time = time + system_time
	mov rdx, [0x3028]      ;; tsc_timestamp
	sub rax, rdx           ;; current_tsc - tsc_timestamp
	;; Check if tsc_shift is negative
	;; For now assume positive shift
	movzx cx, [0x3030 + 28] ;; tsc_shift
	and ecx, 0xFF
	;; Left shift (assumes tsc_shift >= 0)
	shl rax, cl
	;; Multiply by tsc_to_system_mul
	mov rdx, [0x3038]    ;; tsc_to_system_mul
	mul rdx              ;; into RAX:RDX
	;; Right shift by 32 bits
	shr rax, 32
	;; Add the system time base
	mov rdx, [0x3030 + 16] ;; system_time_base
	add rax, rdx           ;; time = time + system_time_base
	pop rdx
	pop rcx
	pop rbx
	ret

.vm64_clock_gettime:
	;; Emulate CLOCK_GETTIME syscall
	;; rdi = clockid
	;; rsi = timespec
	stac
	push rbx
	push rcx
	push rdx
	;; Check if clock_gettime_uses_rdtsc is enabled
	mov bx, WORD [0x2000 + .clock_gettime_uses_rdtsc]
	test bx, bx
	jz .vm64_clock_gettime_syscall
	;; Read the PV clock MSR
	mov ecx, 0x4b564d00  ;; MSR_KVM_WALL_CLOCK_NEW
	mov eax, 0x3000      ;; data
	mov edx, 0           ;; zero high-32 bits
	wrmsr
repeat_wall_clock_read:
	;; Read-fence to ensure we read the latest wall clock
	lfence
	;; Check if the version has changed
	mov edx, DWORD [0x3000] ;; version
	and edx, 1
	test edx, edx
	jnz repeat_wall_clock_read
	;; Read the wall clock
	mov ebx, DWORD [0x3004] ;; sec
	mov ecx, DWORD [0x3008] ;; nsec
	;; Get system time into rax
	call .read_system_time
	;; Add the system time to the wall clock nanoseconds
	add rcx, rax
	;; Store to guest timespec
	mov [rsi], rbx      ;; Store tv_sec
	mov [rsi + 8], rcx  ;; Store tv_nsec
	;; Restore registers
	pop rdx
	pop rcx
	pop rbx
	clac
	;; Return to the caller
	xor eax, eax
	o64 sysret
.vm64_clock_gettime_syscall:
	;; Restore registers
	mov eax, 228 ;; CLOCK_GETTIME
	pop rdx
	pop rcx
	pop rbx
	clac
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
