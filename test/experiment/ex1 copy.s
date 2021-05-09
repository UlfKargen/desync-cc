    test   %rdi,%rdi
    je     L1
    push   %rbp
    mov    %rdi,%rbp
    push   %rbx
    sub    $0x18,%rsp
    cmpl   $0x1c4f,0x18(%rdi)
    jne    L2
    mov    0x6c(%rdi),%eax
    test   %eax,%eax
    je     L3
    cmp    $0xfffffffb,%eax
    jne    L2
L3:
    mov    0x0(%rbp),%eax
    test   %eax,%eax
    je     L4
    sub    $0x1,%eax
    addq   $0x1,0x10(%rbp)
    mov    %eax,0x0(%rbp)
    mov    0x8(%rbp),%rax
    lea    0x1(%rax),%rdx
    mov    %rdx,0x8(%rbp)
    movzbl (%rax),%eax
    add    $0x18,%rsp
    pop    %rbx
    pop    %rbp
    retq   
    nop
L4:
    mov    0x68(%rbp),%ecx
    test   %ecx,%ecx
    jne    L5
L6:
    mov    $0x1,%edx
    lea    0xf(%rsp),%rsi
    mov    %rbp,%rdi
    callq  gz_read
    test   %eax,%eax
    jle    L2
    movzbl 0xf(%rsp),%eax
L12:
    add    $0x18,%rsp
    pop    %rbx
    pop    %rbp
    retq   
L5:
    mov    0x60(%rbp),%rbx
    movl   $0x0,0x68(%rbp)
    test   %rbx,%rbx
    je     L6
    xor    %eax,%eax
    jmp    L7
    nopw   0x0(%rax,%rax,1)
L9:
    mov    %eax,%ecx
    xor    %esi,%esi
    mov    %rcx,%rdx
    cmp    %rbx,%rcx
    jle    L8
    sub    %ebx,%eax
    mov    %ebx,%edx
    mov    %ebx,%ecx
    mov    %eax,%esi
L8:
    add    %rcx,0x8(%rbp)
    add    %rdx,0x10(%rbp)
    mov    %esi,0x0(%rbp)
    sub    %rdx,%rbx
    je     L6
L11:
    mov    0x0(%rbp),%eax
L7:
    test   %eax,%eax
    jne    L9
    mov    0x50(%rbp),%edx
    test   %edx,%edx
    je     L10
    mov    0x80(%rbp),%eax
    test   %eax,%eax
    je     L6
L10:
    mov    %rbp,%rdi
    callq  gz_fetch
    cmp    $0xffffffff,%eax
    jne    L11
L2:
    mov    $0xffffffff,%eax
    jmpq   L12
L1:
    mov    $0xffffffff,%eax
    retq