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
	;; Load 8-bit signed value from system-time
	mov cl, [0x3030 + 28] ;; tsc_shift
	;; Left shift (assumes tsc_shift >= 0)
	test cl, cl
	js .system_time_neg_tsc_shift
	;; If tsc_shift is positive, shift left
	shl rax, cl            ;; rax = rax << tsc_shift
	jmp .system_time_tsc_shift_done
.system_time_neg_tsc_shift:
	;; If tsc_shift is negative, shift right
	neg ecx
	shr rax, cl            ;; rax = rax >> -tsc_shift
.system_time_tsc_shift_done:
	;; Multiply by tsc_to_system_mul
	mov ecx, [0x3038]      ;; tsc_to_system_mul
	mul rcx                ;; into RAX:RDX
	;; Right shift by 32 bits
	shr rax, 32
	;; Add the system time base
	mov rdx, [0x3030 + 16] ;; system_time_base
	add rax, rdx           ;; time = time + system_time_base

	;; Test version is even
	mov ebx, [0x3030]    ;; version
	and ebx, 1
	;;jnp .system_time_already_set ;; read again

	pop rdx
	pop rcx
	pop rbx
	ret

.read_wall_clock:
	push rbx
	push rcx
	push rdx
	;; Check if the wall clock MSR has already been set
	mov eax, [0x3004]    ;; seconds since epoch
	test eax, eax
	jnz .wall_clock_already_set
	;; Read the PV clock MSR
	mov ecx, 0x4b564d00  ;; MSR_KVM_WALL_CLOCK_NEW
	mov eax, 0x3000      ;; data
	mov edx, 0           ;; zero high-32 bits
	wrmsr
.wall_clock_already_set:
	;; Read the wall clock
	mov eax, DWORD [0x3004] ;; sec
	mov ecx, DWORD [0x3008] ;; nsec
	;; Convert to nanoseconds
	mov rbx, 1000000000   ;; 1e9
	mov rdx, 0            ;; clear rdx
	mul rbx               ;; rax = sec * 1e9
	add rax, rcx          ;; rax = sec * 1e9 + nsec
	pop rdx
	pop rcx
	pop rbx
	ret

.vm64_clock_gettime:
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
	;; Get system time into rax
	call .read_system_time
	;; If clockid is CLOCK_MONOTONIC, we are done
	test rdi, rdi
	jnz .finish_up_clock_gettime
	;; If clockid is CLOCK_REALTIME, we need to add
	;; the wall clock time from system time
	call .read_wall_clock
.finish_up_clock_gettime:
	;; RAX now contains the clock time in nanoseconds
	;; Split RAX into seconds and nanoseconds
	mov rdx, 0            ;; 
	mov rbx, 1000000000   ;; 1e9
	div rbx               ;; rax = seconds, rdx = clock_time % 1e9
	;; Store to guest timespec
	mov [rsi], rax        ;; Store tv_sec
	mov [rsi + 8], rdx    ;; Store tv_nsec
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
