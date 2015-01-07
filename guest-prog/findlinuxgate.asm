; Luke McCarthy 2008-06-02
; Find linux-gate VDSO
; http://shaurz.wordpress.com/2008/06/02/finding-linux-gateso1-in-assembly/

format ELF executable
entry start

SYS_EXIT  = 1
SYS_WRITE = 4

STDOUT = 1

AT_SYSINFO = 32

segment readable executable

start:
	mov ecx, [esp]         ; ecx = argc
	lea esi, [8+esp+ecx*4] ; esi = envp
.find_auxv:
	mov eax, [esi]
	lea esi, [esi+4]
	test eax, eax
	jnz .find_auxv
	; esi = auxv
.find_sysinfo:
	mov eax, [esi]
	cmp eax, AT_SYSINFO
	je .found_sysinfo
	lea esi, [esi+8]
	test eax, eax
	jnz .find_sysinfo
	jmp .not_found_sysinfo
.found_sysinfo:
	mov ebp, [esi+4]  ; ebp = sysinfo
	mov eax, SYS_WRITE
	mov ebx, STDOUT
	mov ecx, msg_succ
	mov edx, msg_succ_size
	call ebp  ; syscall
	mov eax, SYS_EXIT
	xor ebx, ebx
	jmp ebp   ; syscall
.not_found_sysinfo:
	mov eax, SYS_WRITE
	mov ebx, STDOUT
	mov ecx, msg_fail
	mov edx, msg_fail_size
	int 0x80
	mov eax, SYS_EXIT
	mov ebx, 1
	int 0x80

segment readable

msg_succ db "linux gate found :-)", 10
msg_succ_size = $-msg_succ
msg_fail db "linux gate not found :-(", 10
msg_fail_size = $-msg_fail
