#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("BINARY")
l{libc = ELF("LIBC")}l
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break main
continue
'''

r{ip, port = "IP", PORT

if len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(ip, port)
el}rif len(sys.argv) > 1 and sys.argv[1] == "-ng":
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

io.interactive()
