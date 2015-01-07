	.file	"chmod.c"
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"/home/rui/abc"
.LC1:
	.string	"failed!, %d\n"
.LC2:
	.string	"OK!!! %p\n"
	.section	.text.startup,"ax",@progbits
	.p2align 4,,15
	.globl	main
	.type	main, @function
main:
.LFB33:
	.cfi_startproc
	pushl	%ebp
	.cfi_def_cfa_offset 8
	.cfi_offset 5, -8
	movl	%esp, %ebp
	.cfi_def_cfa_register 5
	andl	$-16, %esp
	subl	$16, %esp
	movl	$292, 8(%esp)
	movl	$.LC0, 4(%esp)
	movl	$15, (%esp)
	call	syscall
	cmpl	$-1, %eax
	je	.L5
	movl	$.LC0, 8(%esp)
	movl	$.LC2, 4(%esp)
	movl	$1, (%esp)
	call	__printf_chk
	leave
	.cfi_remember_state
	.cfi_restore 5
	.cfi_def_cfa 4, 4
	ret
.L5:
	.cfi_restore_state
	movl	$-1, 8(%esp)
	movl	$.LC1, 4(%esp)
	movl	$1, (%esp)
	call	__printf_chk
	leave
	.cfi_def_cfa 4, 4
	.cfi_restore 5
	ret
	.cfi_endproc
.LFE33:
	.size	main, .-main
	.ident	"GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3"
	.section	.note.GNU-stack,"",@progbits
