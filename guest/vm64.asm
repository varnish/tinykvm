[BITS 64]
global vm64_entry
global vm64_end

org 0x100000
.vm64_entry:
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
	hlt

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
