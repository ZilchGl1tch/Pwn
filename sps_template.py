#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("BINARY")
l{libc = ELF("LIBC")
env = {"LD_PRELOAD":"LIBC"}}l
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
#context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break main
continue
'''

r{ip, port = "IP", PORT

if len(sys.argv) > 1 and sys.argv[1] == "-r":
    io = remote(ip, port)
el}rif len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path, gdbscript=breakpoints)
    
re = lambda a: io.recv(a)
reu = lambda a: io.recvuntil(a)
rl = lambda: io.recvline()
s = lambda a: io.send(a)
sl = lambda a: io.sendline(a)
sla = lambda a,b: io.sendlineafter(a,b)
sa = lambda a,b: io.sendafter(a,b)

io.interactive()
