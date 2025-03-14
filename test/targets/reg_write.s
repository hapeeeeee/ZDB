.global main

.section .data
hex_format: .asciz "%#x"
float_format: .asciz "%.2f"
long_float_format: .asciz "%.2Lf"

.section .text

# syscall for trap
.macro trap
    movq $62, %rax
    movq %r12, %rdi
    movq $5, %rsi
    syscall
.endm

main:
    push %rbp
    movq %rsp, %rbp

    # Syscall for get curr pid
    movq $39, %rax
    syscall
    movq %rax, %r12
    trap

    # Print content in rsi
    leaq hex_format(%rip), %rdi
    movq $0, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    trap

    # Print content in mm0
    movq %mm0, %rsi
    leaq hex_format(%rip), %rdi
    movq $0, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    trap

    # Print content in xmm0
    leaq float_format(%rip), %rdi
    movq $1, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    trap

    # Print content in st0
    subq $16, %rsp
    fstpt (%rsp)
    leaq long_float_format(%rip), %rdi
    movq $0, %rax
    call printf@plt
    movq $0, %rdi
    call fflush@plt
    addq $16, %rsp
    # subq $16, %rsp
    # fstpl (%rsp)
    # leaq long_double_format(%rip), %rdi
    # movq $0, %rax
    # call printf@plt
    # movq $0, %rdi
    # call fflush@plt
    # addq $16, %rsp
    trap

    popq %rbp
    movq $0, %rax
    ret