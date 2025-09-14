[BITS 64]
global vm64_exception
%define INTR_ASM_BASE 0x2000

;; CPU exception frame:
;; 1. stack    rsp+32
;; 2. rflags   rsp+24
;; 3. cs       rsp+16
;; 4. rip      rsp+8
;; 5. code     rsp+0
%macro CPU_EXCEPT 1
ALIGN 0x8
	out 128 + %1, eax
	iretq
%endmacro
%macro CPU_EXCEPT_CODE 1
ALIGN 0x8
	out 128 + %1, eax
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
.vm64_remote_return_addr:
	dw 0x0   ;; Return address after remote call
dd 0x0       ;; Reserved/Padding
.vm64_remote_base:
	dq 0x0   ;; Gigapage base address of the remote VM

ALIGN 0x10
.kvm_wallclock:   ;; 0x2010
	resb 0x10     ;; 16b for KVM Wall-clock
.kvm_system_time: ;; 0x2020
	resb 0x20     ;; 32b for KVM System-time
;; Save state for remote function calls
.remote_state:
	resb 0x100    ;; 256b for remote state saving

ALIGN 0x10
.vm64_syscall:
	cmp ax, 158 ;; PRCTL
	je .vm64_prctl
	cmp ax, 228 ;; CLOCK_GETTIME
	je .vm64_clock_gettime
	cmp eax, 9  ;; MMAP
	je .vm64_mmap
	cmp eax, 0x1F777 ;; ENTRY SYSCALL
	je .vm64_entrycall
	cmp eax, 0x1F778 ;; REMOTE DISCONNECT SYSCALL
	je .vm64_remote_disconnect
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
	out 0, eax
	jmp .vm64_prctl_end

.read_system_time:
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
	sub rax, QWORD [0x2028] ;; current_tsc - tsc_timestamp
	;; Check if tsc_shift is negative
	;; Load 8-bit signed value from system-time
	mov cl, [0x2020 + 28] ;; tsc_shift
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
	mov ecx, [0x2020 + 24] ;; tsc_to_system_mul
	mul rcx                ;; into RAX:RDX
	;; Right shift by 32 bits
	shr rax, 32
	shl rdx, 32
	or rax, rdx          ;; RAX now contains the system time in nanoseconds
	;; Add the system time base
	add rax, [0x2020 + 16] ;; system_time_base

	;; Test version is even
	;;mov ebx, [0x2020]    ;; version
	;;and ebx, 1
	;;jnp .system_time_already_set ;; read again
	ret

.read_wall_clock:
	mov ecx, DWORD [0x2014] ;; sec
	test ecx, ecx
	jnz .read_wall_clock_already_set
	;; Read the wall clock from KVM
	mov ecx, 0x4b564d00
	mov eax, 0x2010 ;; data
	mov edx, 0
	wrmsr
.read_wall_clock_already_set:
	;; Read the wall clock
	mov ecx, DWORD [0x2014] ;; sec
	mov edx, DWORD [0x2018] ;; nsec
	add rax, rdx  ;; Add nanoseconds to RAX
	;; Seconds are in RCX now
	ret

.vm64_clock_gettime:
	;; rdi = clockid
	;; rsi = timespec
	stac
	push rbx
	push rcx
	push rdx
	;; Verify that destination is at least 0x100000
	cmp rsi, 0x100000
	jb .vm64_clock_gettime_error
	;; Get system time into rax
	call .read_system_time
	xor rcx, rcx  ;; Clear RCX: 0 seconds
	;; If clockid is CLOCK_MONOTONIC, we are done
	test rdi, rdi
	jnz .finish_up_clock_gettime
	;; If clockid is CLOCK_REALTIME, we need to add
	;; the wall clock time from system time
	call .read_wall_clock
	;; RCX now has the seconds from the wall clock
.finish_up_clock_gettime:
	;; RAX now contains the clock time in nanoseconds
	;; Split RAX into seconds and nanoseconds
	xor rdx, rdx          ;; Clear RDX for division
	mov rbx, 1000000000   ;; 1e9
	div rbx               ;; rax = seconds, rdx = clock_time % 1e9
	;; Add the wall-clock seconds to RAX from RCX
	add rax, rcx          ;; Add seconds to RAX
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
.vm64_clock_gettime_error:
	mov rax, -14 ;; EFAULT
	o64 sysret
.vm64_clock_gettime_fallback:
	;; Fallback to host syscall trap
	pop rdx
	pop rcx
	pop rbx
	clac
	mov eax, 228 ;; CLOCK_GETTIME
	out 0, eax
	o64 sysret

.vm64_mmap:
	out 0, eax   ;; MMAP syscall
	;; If the fd is -1, we are done
	cmp r8, -1
	je .vm64_mmap_done
	;; Otherwise, reload page tables
	stac
	push rax
	mov rax, cr3
	mov cr3, rax
	pop rax
	clac
.vm64_mmap_done:
	o64 sysret

.vm64_gettimeofday:
	mov eax, 96 ;; gettimeofday
	out 0, eax
	ret

.vm64_dso:
	mov eax, .vm64_gettimeofday
	ret

.vm64_remote_disconnect:
	out 0, eax
	;; RAX contains the original FSBASE of this VM
	stac
	;; Write to FSBASE MSR
	push rcx
	push rdx
	mov ecx, 0xC0000100  ;; FSBASE
	mov rdx, rax
	shr rdx, 32
	wrmsr
	pop rdx
	pop rcx
	clac
	;; Reset pagetables
	mov rax, cr3
	mov cr3, rax
	o64 sysret

.vm64_entrycall:
	;; Reset pagetables
	mov rax, cr3
	mov cr3, rax
	o64 sysret

.vm64_reentrycall:
	o64 sysret

.vm64_page_fault:
	push rax
	push rdi
	mov rdi, cr2 ;; Faulting address
	out 128 + 14, eax
	invlpg [rdi]
	pop rdi
	test eax, eax
	jnz .vm64_remote_page_fault
	pop rax
.vm64_pop_code:
	add rsp, 8
	iretq

.vm64_remote_page_fault:
	;; RAX: Remote FSBASE
	;; Write to FSBASE MSR
	push rcx
	push rdx
	mov ecx, 0xC0000100  ;; FSBASE
	mov rdx, rax
	shr rdx, 32
	wrmsr
	pop rdx
	pop rcx

	;; Make the next function call return to a custom system call location
	push rbx
	;; Get remote-disconnect syscall address
	mov rax, [INTR_ASM_BASE + .vm64_remote_return_addr]
	;; Get original stack pointer
	mov rbx, [rsp + 16 + 32] ;; Original RSP
	;; Overwrite the return address
	stac
	mov [rbx], rax ;; Return address
	clac

	pop rbx
	pop rax
	add rsp, 8 ;; Skip error code

	iretq

.vm64_timeout:
	out 128 + 33, eax
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
