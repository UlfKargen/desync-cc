main:
	xorl	%eax, %eax
	xorl	%ecx, %ecx
.L1:
	addl	$1, %eax
	cmpl	$10, %eax
	jne	.L2
mainfallthrough:
	movl	$0, %ecx
	movl	$0, %eax
	ret
.L2:
	addl	$1, %ecx
	cmpl	$10, %ecx
	jne .L1
L1fallthrough:
	movl	$0, %ecx
	movl	$0, %eax
	ret
selflooptest:
	xorl	%eax, %eax
.Loop:
	addl	$1, %eax
	cmpl	$10, %eax
	jne	.Loop
	movl	$0, %eax
	ret
