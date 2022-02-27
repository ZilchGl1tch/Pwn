#!/usr/bin/env python3
from dn3 import *
from time import sleep

exe = ELF("BINARY")
l{
libc = ELF("LIBC")
}l
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"
#context.aslr = False

global io
breakpoints = '''
break main
'''+"continue\n"*1

r{host, port = "IP",PORT

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = remote(host,port)
el}rif len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path,gdbscript=breakpoints)
    
DeathNot3(io)