	.file	"main.c"
	.text
	.globl	string_length
	.type	string_length, @function
string_length:
.LFB0:
	.cfi_startproc
	
    xorq %rax, %rax
    jz desync_jump_0

desync_point_0:

    xorq %rax, %rax
    jz desync_jump_0

desync_point_0:
nop
nop
desync_jump_0:
nop
nop
desync_jump_0:
pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movq	%rdi, -24(%rbp)
	movl	$0, -4(%rbp)
	jmp	.L2
.L3:
	addq	$1, -24(%rbp)
	addl	$1, -4(%rbp)
.L2:
	movq	-24(%rbp), %rax
	movzbl	(%rax), %eax
	testb	%al, %al
	jne	.L3
	movl	-4(%rbp), %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE0:
	.size	string_length, .-string_length
	.globl	parse_int
	.type	parse_int, @function
parse_int:
.LFB1:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	
    xorq %rbp, %rbp
    jz desync_jump_1

desync_point_1:
nop
nop
desync_jump_1:
movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	
    xorq %rax, %rax
    jz desync_jump_1

desync_point_1:
nop
nop
desync_jump_1:
subq	$24, %rsp
	movq	%rdi, -24(%rbp)
	movl	$0, -12(%rbp)
	movl	$1, -8(%rbp)
	movq	-24(%rbp), %rax
	movq	%rax, %rdi
	call	string_length
	movl	%eax, -4(%rbp)
	jmp	.L6
.L7:
	
    xorq %rax, %rax
    jz desync_jump_2

desync_point_2:
nop
nop
nop
desync_jump_2:
movl	-4(%rbp), %eax
	movslq	%eax, %rdx
	movq	-24(%rbp), %rax
	addq	%rdx, %rax
	movzbl	(%rax), %eax
	movsbl	%al, %eax
	subl	$48, %eax
	imull	-8(%rbp), %eax
	addl	%eax, -12(%rbp)
	movl	-8(%rbp), %edx
	movl	%edx, %eax
	sall	$2, %eax
	addl	%edx, %eax
	addl	%eax, %eax
	movl	%eax, -8(%rbp)
.L6:
	movl	-4(%rbp), %eax
	leal	-1(%rax), %edx
	movl	%edx, -4(%rbp)
	testl	%eax, %eax
	jg	.L7
	movl	-12(%rbp), %eax
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE1:
	.size	parse_int, .-parse_int
	.globl	vector3_square
	.type	vector3_square, @function
vector3_square:
.LFB2:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	
    xorq %rbp, %rbp
    jz desync_jump_2

desync_point_2:
nop
nop
nop
desync_jump_2:

    xorq %rbp, %rbp
    jz desync_jump_3

desync_point_3:

    xorq %rbp, %rbp
    jz desync_jump_3

desync_point_3:
nop
nop
nop
desync_jump_3:

    xorl %eax, %eax
    jz desync_jump_4

desync_point_4:
nop
nop
desync_jump_4:
nop
nop
nop
desync_jump_3:
movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	%edi, -4(%rbp)
	movl	%esi, -8(%rbp)
	movl	%edx, -12(%rbp)
	movl	-4(%rbp), %eax
	imull	%eax, %eax
	movl	%eax, %edx
	movl	-8(%rbp), %eax
	imull	%eax, %eax
	addl	%eax, %edx
	movl	-12(%rbp), %eax
	imull	%eax, %eax
	addl	%edx, %eax
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE2:
	.size	vector3_square, .-vector3_square
	.globl	asdf
	.bss
	.align 4
	.type	asdf, @object
	.size	asdf, 4
asdf:
	.zero	4
	.text
	.globl	test123
	.type	test123, @function
test123:
.LFB3:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	
    
    xorq %rbp, %rbp
    jz desync_jump_5

desync_point_5:
nop
nop
desync_jump_5:
xorl %eax, %eax
    jz desync_jump_4

desync_point_4:
nop
nop
desync_jump_4:
movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	movl	asdf(%rip), %eax
	addl	$1, %eax
	movl	%eax, asdf(%rip)
	nop
	popq	%rbp
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE3:
	.size	test123, .-test123
	.section	.rodata
.LC0:
	.string	"Result: %d\n"
	.text
	.globl	main
	.type	main, @function
main:
.LFB4:
	.cfi_startproc
	pushq	%rbp
	.cfi_def_cfa_offset 16
	.cfi_offset 6, -16
	movq	%rsp, %rbp
	.cfi_def_cfa_register 6
	pushq	%rbx
	subq	$72, %rsp
	.cfi_offset 3, -24
	movl	%edi, -68(%rbp)
	movq	%rsi, -80(%rbp)
	
    xorq %rax, %rax
    jz desync_jump_6

desync_point_6:
nop
nop
nop
desync_jump_6:
movq	%fs:40, %rax
	movq	%rax, -24(%rbp)
	xorl	%eax, %eax
	cmpl	$4, -68(%rbp)
	je	.L13
	
    xorq %rcx, %rcx
    jz desync_jump_5

desync_point_5:
nop
nop
desync_jump_5:
movl	$-1, %eax
	jmp	.L17
.L13:
	movl	$0, %eax
	call	test123
	movl	$0, -36(%rbp)
	movl	$0, -32(%rbp)
	movl	$0, -28(%rbp)
	leaq	-36(%rbp), %rax
	movq	%rax, -48(%rbp)
	movl	$1, -52(%rbp)
	jmp	.L15
.L16:
	movl	-52(%rbp), %eax
	
    xorq %rax, %rax
    jz desync_jump_7

desync_point_7:
nop
desync_jump_7:
cltq
	leaq	0(,%rax,8), %rdx
	movq	-80(%rbp), %rax
	addq	%rdx, %rax
	movq	(%rax), %rax
	movq	-48(%rbp), %rbx
	
    xorq %rdi, %rdi
    jz desync_jump_6

desync_point_6:
nop
nop

    xorq %rdi, %rdi
    jz desync_jump_8

desync_point_8:
nop
desync_jump_8:
nop
desync_jump_6:
leaq	4(%rbx), %rdx
	movq	%rdx, -48(%rbp)
	movq	%rax, %rdi
	call	parse_int
	movl	%eax, (%rbx)
	addl	$1, -52(%rbp)
.L15:
	movl	-52(%rbp), %eax
	cmpl	-68(%rbp), %eax
	jl	.L16
	movl	-28(%rbp), %edx
	movl	-32(%rbp), %ecx
	movl	-36(%rbp), %eax
	movl	%ecx, %esi
	movl	%eax, %edi
	call	vector3_square
	movl	%eax, %esi
	leaq	.LC0(%rip), %rdi
	movl	$0, %eax
	call	printf@PLT
	
    xorq %rcx, %rcx
    jz desync_jump_9

desync_point_9:
nop
nop
desync_jump_9:

    xorq %rcx, %rcx
    jz desync_jump_10

desync_point_10:
nop
desync_jump_10:
movl	$0, %eax
.L17:
	movq	-24(%rbp), %rcx
	subq	%fs:40, %rcx
	je	.L18
	call	__stack_chk_fail@PLT
.L18:
	movq	-8(%rbp), %rbx
	leave
	.cfi_def_cfa 7, 8
	ret
	.cfi_endproc
.LFE4:
	.size	main, .-main
	.ident	"GCC: (GNU) 10.2.0"
	.section	.note.GNU-stack,"",@progbits
