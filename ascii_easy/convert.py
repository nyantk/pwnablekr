from pwn import *
f = open("./roplib.txt", "r")
l = f.readlines()
f.close()

def is_ascii(c):
    c = ord(c)
    if(c>=0x20 and c<=0x7f):
        return 1
    return 0

adddrs = []
for s in l:
    if(s[:2] == "0x"):
        addr = pack(0x5555e000+int(s[:10], 16))
        addr_is_ascii = True
        for a in addr:
            if(not is_ascii(a)):
                addr_is_ascii = False
        if addr_is_ascii:
            adddrs.append(s)
    else:
        adddrs.append(s)

f = open("./roplibcosutom.txt", "w")
f.writelines(adddrs)
f.close()
