;Copyright (c) 1999 Konstantin Boldyshev <konst@linuxassembly.org>
;
;"hello, world" in assembly language for Linux
;
;to compile:
;
;nasm -f elf hello.asm				#generate 32-bit elf object file
;ld -s -o hello hello.o
;ld -m elf_i386 -s -o hello hello.o #generate 32-bit executable in x86_64

section	.text
    global _start			;must be declared for linker (ld)

_start:					;tell linker entry point

	mov	edx,len	;message length
	mov	ecx,msg	;message to write
	mov	ebx,1	;file descriptor (stdout)
	mov	eax,4	;system call number (sys_write)
	int	0x80	;call kernel

	mov	eax,1	;system call number (sys_exit)
	int	0x80	;call kernel

section	.data

msg	db	'Hello, world!',0xa	;our dear string
len	equ	$ - msg			;length of our dear string
